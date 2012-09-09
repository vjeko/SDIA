
#include "graph.hh"
#include <iterator>


void graph::update_receive(
    const Openflow_event& ofe,
    const v1::ofp_packet_in& pi) {

  RPC rpc;
  rpc.set_type(RPC::DataReceive);

  DataReceive* update = rpc.MutableExtension(DataReceive::msg);

  const auto size = boost::asio::buffer_size(pi.packet());
  const char* p = boost::asio::buffer_cast<const char*>(pi.packet());
  std::string s(p, size);

  dp_link rcv(
      ofe.dp.id().as_host(),
      pi.in_port(),
      domain_id_,
      dp_link::OPENFLOW);
  update->set_data( s );

  const auto it = vertex_map_.find( rcv );
  BOOST_ASSERT(it != vertex_map_.end());
  vertex_t rcvV = it->second;

  const auto it_rcv = edge_map_.find(rcv);
  BOOST_ASSERT(it_rcv != edge_map_.end());
  vertex_t sndV = opposite_vertex(it_rcv->second, rcvV);

  update->set_srcv(sndV);

  BOOST_FOREACH(auto& session, server_->sessions_) {
    session->write(rpc);
  }
}



session::session(
    boost::asio::io_service& io_service,
    graph* const g)
  : socket_(io_service),
    graph_(g) {}



tcp::socket& session::socket() {
  return socket_;
}



void session::start() {

  boost::asio::async_read(socket_, boost::asio::buffer(len_),
      boost::bind(&session::handle_read_size, this,
        boost::asio::placeholders::error,
        boost::asio::placeholders::bytes_transferred));
}



void session::handle_read_size(
    const boost::system::error_code& error,
    size_t bytes_transferred) {

  int32_t size = ntohl(len_[0]);

  boost::asio::async_read(socket_, boost::asio::buffer(data_, size),
      boost::bind(&session::handle_read, this,
        boost::asio::placeholders::error,
        boost::asio::placeholders::bytes_transferred));

}



void session::handlePacketInResponse(RPC& rpc) {

  const PacketInResponse response = rpc.GetExtension(PacketInResponse::msg);

  if(response.has_midv()) {
    graph_->establish(
        response.cookie(),
        response.match(),
        response.srcv(),
        response.midv(),
        response.dstv());
  } else if (response.has_action()) {
    graph_->establish(
        response.cookie(),
        response.match(),
        response.srcv(),
        response.dstv(),
        response.action());
  } else {
    graph_->establish(
        response.cookie(),
        response.match(),
        response.srcv(),
        response.dstv());
  }
}



void session::andleDataPush(RPC& rpc) {

  const DataPush update = rpc.GetExtension(DataPush::msg);

  graph::vertex_t srcV(update.srcv());
  graph::vertex_t dstV(update.dstv());

  auto result = boost::edge(srcV, dstV, graph_->g);
  if (result.second) {

    auto s = graph_->edge_property_[result.first];
    auto it = s.begin();

    for (; it != s.end(); std::advance(it, 1)) {
      if ( (it->domain_ == graph_->domain_id_) &&
           (it->type_ == dp_link::OPENFLOW))
        break;
    }

    BOOST_ASSERT(it != s.end());

    BOOST_FOREACH(auto& dev, graph_->device_map) {
      if (dev.first == it->datapath_) {
        auto sp = new std::string(update.data());
        boost::asio::const_buffer buffer(sp->c_str(), sp->size());
        graph_->send_blob(buffer, dev.second, it->port_);
      }
    }
  } else {
    std::cout << "unable to find the edge" << std::endl;
  }

}


void session::handleInitRequest(RPC& rpc) {

  RPC rpcResponse;
  rpcResponse.set_type(RPC::InitResponse);
  InitResponse* update = rpcResponse.MutableExtension(InitResponse::msg);

  update->set_domain(graph_->domain_id_);
  write(rpcResponse);
}



void session::handle_read(
    const boost::system::error_code& error,
    size_t bytes_transferred) {

  if (!error) {

    std::string raw(data_.c_array(), bytes_transferred);

    RPC rpc;;
    rpc.ParseFromString( raw );

    if (rpc.type() == RPC::PacketInResponse) {
      handlePacketInResponse(rpc);
    } else if (rpc.type() == RPC::DataPush) {\
      andleDataPush(rpc);
    } else if (rpc.type() == RPC::InitRequest) {
      handleInitRequest(rpc);
    }

    boost::asio::async_read(socket_, boost::asio::buffer(len_),
        boost::bind(&session::handle_read_size, this,
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred));

  } else {
    std::cout << "connection lost... :(" << std::endl;
    //delete this;
  }
}



void session::write(RPC& rpc) {
  const size_t size = rpc.ByteSize();
  uint8_t* array = new uint8_t[size];
  rpc.SerializeToArray(array, size);
  write(array, size);
}




void session::write(const uint8_t* data, size_t size) {
    boost::asio::async_write(socket_, boost::asio::buffer(data, size),
        boost::bind(&session::handle_write, this,
          boost::asio::placeholders::error, data, size));
}



void session::handle_write(
    const boost::system::error_code& error,
    const uint8_t* data, size_t size) {
  delete data;
}




server::server(
    boost::asio::io_service& io_service,
    const uint16_t port, graph* const g)

  : io_service_(io_service),
    acceptor_(io_service, tcp::endpoint(tcp::v4(), port)),
    graph_(g) {
  start_accept();
}


void server::handle_accept(
    boost::shared_ptr<session> new_session,
    const boost::system::error_code& error) {

  if (!error) {
    new_session->start();
    sessions_.push_back(new_session);
  }

  start_accept();
}



void server::start_accept() {

  using boost::shared_ptr;

  auto new_session = boost::shared_ptr<session>(new session(io_service_, graph_));
  acceptor_.async_accept(new_session->socket(),
      boost::bind(&server::handle_accept, this, new_session,
        boost::asio::placeholders::error));
}



void graph::ism_interface() {

  const auto& args = ctxt->get_config_list("args");
  const uint16_t port = boost::lexical_cast<uint16_t>(args.front());
  std::cout << "Listening on port " << port << std::endl;

  try {
    boost::asio::io_service io_service;
    server_ = boost::shared_ptr<server>(
        new server(io_service, port, this));
    io_service.run();
  } catch (std::exception& e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }

}

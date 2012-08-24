#include "graph.hh"

#include <boost/asio.hpp>


template<typename V, typename Q>
std::pair<typename Q::key_type, typename Q::key_type> graph::ordering(V v, Q q) {

  typename Q::key_type in, out;
  typename Q::iterator it = q.begin();

  if (vertex_property_[v].get_datapath() == it->get_datapath()) {
    in = *it; out = *(++it);
  } else {
    out = *it; in = *(++it);
  }

  return std::make_pair(in, out);
}



void graph::distribute_packet(
    const v1::ofp_packet_in& pi,
    const uint32_t label,
    const vertex_t srcV) {

  RPC rpc;
  rpc.set_type(RPC::PacketInRequest);

  PacketInRequest* packet = rpc.MutableExtension(PacketInRequest::msg);

  const auto size = boost::asio::buffer_size(pi.packet());
  const char* p = boost::asio::buffer_cast<const char*>(pi.packet());
  std::string s(p, size);
  packet->set_packet(s);
  packet->set_srcv(srcV);
  packet->set_cookie(label);

  BOOST_FOREACH(auto& session, server_->sessions_) {
    session->write(rpc);
  }
}



void graph::distribute_topology(std::string s) {
  RPC rpc;
  rpc.set_type(RPC::Topology);

  Topology* pr = rpc.MutableExtension(Topology::msg);
  pr->set_dot(s);

  BOOST_FOREACH(auto& session, server_->sessions_) {
    session->write(rpc);
  }
}

/*
 * Output the current topology to a dot file.
 */
void graph::write_topology() {

  sleep(1);

  while(true) {

    std::ostringstream stream;
    boost::write_graphviz(stream, g, label_writer<vertex_property_t>(vertex_property_));
    distribute_topology(stream.str());

    sleep(2);
  }
}

template<class Type>
Type& pull_type(
    uint8_t* p,
    size_t offset) {
  Type* t = (Type*) (p + offset);
  return *t;
}

template<class Type>
const Type& pull_type(
    const uint8_t* p,
    size_t offset) {
  const Type* t = (const Type*) (p + offset);
  return *t;
}

template<class Type>
const Type& pull_type(
		const boost::asio::const_buffer& buffer,
		size_t offset) {
	const uint8_t* p = boost::asio::buffer_cast<const uint8_t*>(buffer);
	return pull_type<Type>(p, offset);
}


bool is_unicast(const vigil::ethernetaddr& e) {

  if ((!e.is_broadcast()) && (!e.is_multicast())) return true;
  return false;
}

bool is_unicast(const v1::ofp_match& flow) {
  if (is_unicast(flow.dl_src()) && is_unicast(flow.dl_dst())) return true;
  return false;
}

uint32_t get_flow(const ip6_hdr& ip6) {
  const uint8_t next_header = ip6.ip6_ctlun.ip6_un1.ip6_un1_nxt;
  const uint32_t flow_label =
      (ntohl(ip6.ip6_ctlun.ip6_un1.ip6_un1_flow) << 12) >> 12;

  return flow_label;
}


dp_node::transaction_t graph::get_transaction_id() {
  static uint64_t transaction_id;
  return ++transaction_id;
}



graph::vertex_t graph::opposite_vertex(edge_t e, vertex_t swV) {

  vertex_t resultV;

  if (swV == target(e, g))
    resultV = source(e, g);
  else if (swV == source(e, g))
    resultV = target(e, g);
  else
    BOOST_ASSERT(false);

  return resultV;
}



#include <ctype.h>
#include <stdio.h>

void hexdump(const void *ptr, int buflen) {
  unsigned char *buf = (unsigned char*)ptr;
  int i, j;
  for (i=0; i<buflen; i+=16) {
    printf("%06x: ", i);
    for (j=0; j<16; j++)
      if (i+j < buflen)
        printf("%02x ", buf[i+j]);
      else
        printf("   ");
    printf(" ");
    for (j=0; j<16; j++)
      if (i+j < buflen)
        printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
    printf("\n");
  }
}

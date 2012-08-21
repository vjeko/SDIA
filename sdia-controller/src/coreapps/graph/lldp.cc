
#include "graph.hh"
#include <boost/foreach.hpp>

  using namespace vigil;
  using namespace openflow;

struct lldp_header {
  uint32_t domain_id;
  uint16_t port_number;
  uint64_t dp;
} __attribute__ ((__packed__));


dp_link graph::extract_lldp(
    const boost::asio::const_buffer& buffer) {

  const auto& l = pull_type<lldp_header>(buffer, sizeof(struct eth_header));

  const auto datapath = l.dp;
  const auto port = l.port_number;
  const auto domain = l.domain_id;

  auto node_type = dp_link::OPENFLOW;

  if (l.domain_id != domain_id_) {
    node_type = dp_link::OTHER_DOMAIN;
  }

  return dp_link(datapath, port, domain, node_type);

}

template<typename Buffer>
void graph::send_blob(
    Buffer buffer,
    boost::shared_ptr<Openflow_datapath> dp,
    const uint16_t port_num) {

  auto* po = new v1::ofp_packet_out;

  po->in_port(v1::ofp_phy_port::OFPP_NONE);
  po->packet(buffer);
  po->buffer_id(-1);

  auto* ao = new v1::ofp_action_output;
  ao->port(port_num);
  po->add_action(ao);
  dp->send(po);

  //std::cout << dp.get()->id().as_host() << ":" << port_num << std::endl;

  /*
  auto po = v1::ofp_packet_out();

  po.in_port(v1::ofp_phy_port::OFPP_NONE)
  .packet(buffer)
  .buffer_id(-1);

  auto ao = v1::ofp_action_output();
  ao.port(port_num);
  po.add_action(&ao);
  dp->send(&po);
   */
}



void graph::send_lldp() {

  while(true) {

    sleep(2);

    BOOST_FOREACH(const auto& pair, device_map) {

      auto dp_p = pair.second;

      for (int i = 0; i < dp_p->features.n_ports_; i++) {

        const uint16_t port_num = dp_p->features.ports_[i].port_no();

        if (port_num > 100) continue;

        const size_t size = sizeof(struct eth_header) + sizeof(struct lldp_header) + 20;
        uint8_t* raw_of = new uint8_t[size];

        memset(raw_of, 0, size);

        auto& eth = pull_type<eth_header>(raw_of, 0);
        eth.eth_type = ethernet::LLDP;

        auto& lldp = pull_type<lldp_header>(raw_of, sizeof(struct eth_header));
        lldp.port_number = port_num;
        lldp.dp = dp_p->id().as_host();
        lldp.domain_id = domain_id_;

        boost::asio::mutable_buffer buffer(raw_of, size);
        send_blob(buffer, dp_p, port_num);
      }
    }
  }

}

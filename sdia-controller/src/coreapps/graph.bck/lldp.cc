
#include "graph.hh"
#include <boost/foreach.hpp>

  using namespace vigil;
  using namespace openflow;

struct lldp_header {
  uint16_t port_number;
  uint64_t dp;
} __attribute__ ((__packed__));


dp_link graph::extract_lldp(
    const boost::asio::const_buffer& buffer,
    const dp_node::transaction_t transaction_id) {

  const lldp_header &l = pull_type<lldp_header>(buffer, sizeof(struct eth_header));

  const uint64_t datapath = l.dp;
  const uint16_t port = l.port_number;

  return dp_link(datapath, port, dp_link::OPENFLOW, transaction_id);

}



void graph::send_lldp() {

  while(true) {

    sleep(2);

    BOOST_FOREACH(const auto& pair, device_map) {

      auto dp_p = pair.second;

      for (int i = 0; i < dp_p->features.n_ports_; i++) {

        uint16_t port_num = dp_p->features.ports_[i].port_no();
        size_t size = sizeof (struct eth_header) + sizeof (struct lldp_header) + 20;
        uint8_t* raw_of = new uint8_t[size];
        memset(raw_of, 0, size);

        boost::asio::mutable_buffer buffer(raw_of, size);

        struct eth_header *eh = (eth_header*) ( raw_of );
        eh->eth_type = ethernet::LLDP;
        eh->eth_dst[2] = 0xa;
        eh->eth_src[2] = 0xd;


        struct lldp_header *lldp_hdr = (lldp_header*)( raw_of +
            sizeof(struct eth_header) );
        lldp_hdr->port_number = port_num;
        lldp_hdr->dp = dp_p->id().as_host();

        //printf("Sending LLDP %016lx:%d\n", lldp_hdr->dp, lldp_hdr->port_number);
        auto po = v1::ofp_packet_out()
          .in_port(v1::ofp_phy_port::OFPP_NONE)
          .packet(buffer);
        auto ao = v1::ofp_action_output().port(port_num);
        po.add_action(&ao);
        dp_p->send(&po);
      }
    }
  }

}

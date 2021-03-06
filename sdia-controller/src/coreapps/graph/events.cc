#include "graph.hh"
#include <iostream>
#include <functional>
#include <algorithm>


void graph::install() {
  boost::thread* topo = tg_.create_thread(std::bind(&graph::write_topology, this));
  boost::thread* lldp = tg_.create_thread(std::bind(&graph::send_lldp, this));
  boost::thread* ism = tg_.create_thread(std::bind(&graph::ism_interface, this));

  tg_.add_thread(ism);
  tg_.add_thread(topo);
  tg_.add_thread(lldp);
}



void graph::configure() {

  if (ctxt->has("args")) {

    const auto& args = ctxt->get_config_list("args");

    if (args.size() < 1) {
        std::runtime_error("port not specified!");
    }

  }


  register_handler("Openflow_datapath_join_event", (boost::bind(&graph::join, this, _1)));
  register_handler("ofp_packet_in", (boost::bind(&graph::handle, this, _1)));
}



Disposition graph::join(const Event& e) {
  auto& je = assert_cast<const Openflow_datapath_join_event&>(e);
  device_map[je.dp.get()->id().as_host()] = je.dp;

  return CONTINUE;
}

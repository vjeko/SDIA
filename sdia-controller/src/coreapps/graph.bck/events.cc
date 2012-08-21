#include "graph.hh"
#include <iostream>
#include <functional>
#include <algorithm>


void graph::install() {
  boost::thread* topo = tg_.create_thread(std::bind(&graph::write_topology, this));
  boost::thread* lldp = tg_.create_thread(std::bind(&graph::send_lldp, this));
  tg_.add_thread(topo);
  tg_.add_thread(lldp);
}



void graph::configure() {
  register_handler("Openflow_datapath_join_event", (boost::bind(&graph::join, this, _1)));
  register_handler("ofp_packet_in", (boost::bind(&graph::handle, this, _1)));
}



Disposition graph::join(const Event& e) {
  auto& je = assert_cast<const Openflow_datapath_join_event&>(e);
  device_map[je.dp.get()->id().as_host()] = je.dp;

  return CONTINUE;
}

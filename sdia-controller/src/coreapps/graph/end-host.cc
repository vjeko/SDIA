#include "graph.hh"


template<class F>
graph::vertex_t graph::collect(
	      const Openflow_event& ofe,
	      const v1::ofp_packet_in& pi) {

  mutex_t::scoped_lock big_lock(big_mutex_);

  using namespace boost;

  vertex_t sndV, rcvV;
  edge_t e;

  v1::ofp_match flow;
  flow.from_packet(pi.in_port(), pi.packet());

  bool modified_vertex = false;
  bool modified_edge = false;

  dp_link rcv(ofe.dp.id().as_host(), pi.in_port(), dp_link::OPENFLOW);
  dp_link snd(flow.dl_src().hb_long(), pi.in_port(), dp_node::HOST);

  // Let's see what's located on the incoming port...
  auto it_rcv = edge_map_.find(rcv);

  if (it_rcv == edge_map_.end()) {
    std::cout << "discovered a new switch" << std::endl;

    modified_vertex = modified_vertex | update_vertex(snd, sndV);
    modified_vertex = modified_vertex | update_vertex(rcv, rcvV);

    if (vertex_property_[sndV].get_type() == dp_link::OPENFLOW) {
      vertex_property_[sndV].type_ == dp_link::HOST;
    }

    tie(e, modified_edge) = add_edge(sndV, rcvV, g);

    std::cout
      << "EDGE (NEW): " << e
      << "(" << rcvV << rcv.print() << ")"
      << "(" << sndV << snd.print() << ")" << std::endl;

    weight_property_[e] = NORMAL_WEIGHT;

    edge_property_[e].insert(rcv);
    edge_property_[e].insert(snd);

    edge_map_[rcv] = e;
    edge_map_[snd] = e;

    //link_map_[rcv].clear();
    //link_map_[snd].clear();

    link_map_[rcv].insert(rcv);
    link_map_[snd].insert(snd);

    build_spanning_tree();
  }

  // Register the address.
  link_map_[rcv].insert(rcv);

  it_rcv = edge_map_.find(rcv);
  BOOST_ASSERT( it_rcv != edge_map_.end() );
  e = it_rcv->second;

  rcvV = vertex_map_[rcv];
  sndV = opposite_vertex(e, rcvV);

  dp_link::NodeTypeE node_type = vertex_property_[sndV].get_type();

  if (node_type == dp_link::HOST) {
    const link_map_t::mapped_type& link_map = link_map_[snd];

    link_map_[snd].insert(snd);
    vertex_map_[snd] = sndV;

   /*
    * If more than one address is encountered, assume
    * we're dealing with a rcvitch.
    */
    if (link_map.size() > 1) vertex_property_[sndV].type_ = dp_link::SWITCH;
    else BOOST_ASSERT(link_map.size() == 1);

  } else if (node_type == dp_link::SWITCH) {

    vertex_map_[snd] = sndV;
  } else if (node_type == dp_link::OPENFLOW) {

  }
  //return e.m_source;
  return sndV;

}

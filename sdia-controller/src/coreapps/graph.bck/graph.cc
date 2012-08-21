#include "graph.hh"
#include "assert.hh"
#include "component.hh"
#include "fnv_hash.hh"
#include "hash_set.hh"
#include "vlog.hh"
#include "omega.h"

#include <ctime>

#include <cstdio>
#include "netinet++/ethernetaddr.hh"
#include "netinet++/ethernet.hh"
#include "openflow/nicira-ext.h"

#include <inttypes.h>

#include <algorithm>
#include <numeric>
#include <iterator>
#include <exception>
#include <deque>

#include <boost/foreach.hpp>
#include <boost/integer.hpp>
#include <boost/assert.hpp>

#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/variate_generator.hpp>

#include <boost/graph/dijkstra_shortest_paths_no_color_map.hpp>
#include <boost/range.hpp>

#include "helper.cc"
#include "lldp.cc"
#include "events.cc"
#include "end-host.cc"
#include "ism.cc"
#include "commands.hh"

using namespace vigil;
using namespace openflow;


/*
 * START HERE 0:
 *
 * Whenever a packet arrives at a switch and it does not match any
 * of the flows, this function gets invoked.
 */
Disposition graph::handle(const Event& e) {
  /*
   * There are different types of event -- join, packet-in, flow-expire...
   * This function is bound to the packet-in event.
   */
  auto ofe = assert_cast<const Openflow_event&>(e);
  auto pi = *(assert_cast<const v1::ofp_packet_in*>(ofe.msg));
  /*
   * When you want to output a packet that was sent to you
   * (via the controller), you _have_ to refer to its buffer ID.
   */

  v1::ofp_match flow;
  flow.from_packet(pi.in_port(), pi.packet());


  if (flow.dl_type() == OFP_DL_TYPE_NOT_ETH_TYPE) {
    return CONTINUE;
  }

  /*
   * Discovery protocol.
   *
   * Constructs the non end-host part of the topology.
   */

  if (flow.dl_type() == ntohs(ethernet::LLDP)) {
    neighbor_discovery(ofe, pi);
    return CONTINUE;
  }

  /* Handle only IP6 packets. */
  if (flow.dl_type() != ntohs(ethernet::IPV6)) {
    return CONTINUE;
  }

  /*
   * Collect end-host L2 and L3 information.  Constructs the end-host
   * part of the topology.
   *
   * TODO: Make sure we do not collect non-unicast IP6 addresses.
   */

  if (is_unicast(flow.dl_src())) {
    collect(ofe, pi);
  }

  /*
   * This is the part that does the actual routing.
   *
   * TODO: Make sure we do not handle non-unicast IP6 addresses.
   */

  if (is_unicast(flow)) {
    establish(ofe, pi);
  } else {
    /* Otherwise, just flood. */
    //flood_spanning_tree(ofe, pi);
  }
  return CONTINUE;
}



/*
 * Used by the topology construction subsystem.
 */
bool graph::update_vertex(const dp_node n, vertex_t& v) {

  bool modified_vertex = false;
  vertex_map_t::iterator pos;

  boost::tie(pos, modified_vertex) = vertex_map_.insert(
      std::make_pair(n, vertex_t())
  );

  if (modified_vertex) {
    pos->second = boost::add_vertex(g);
    v = pos->second;

    vertex_property_[v] = n;
    vertex_map_[n] = v;

    std::cout
        << "adding vertex " << v
        << " with associated datapath " << n.datapath_ << std::endl;
  }

  v = pos->second;

  return modified_vertex;
}


/*
 * Used by the topology construction subsystem.
 */
void graph::neighbor_discovery(
    const Openflow_event& ofe,
    const v1::ofp_packet_in& pi) {

  mutex_t::scoped_lock big_lock(big_mutex_);

  v1::ofp_match flow;
  flow.from_packet(pi.in_port(), pi.packet());

  const dp_node::transaction_t transaction_id = get_transaction_id();
  dp_link rcv(
      ofe.dp.id().as_host(),
      pi.in_port(),
      dp_link::OPENFLOW,
      transaction_id);
  dp_link snd = extract_lldp(pi.packet(), transaction_id);

  rcv.opposite_ = snd.datapath_;
  snd.opposite_ = rcv.datapath_;


  vertex_t sndV, rcvV;
  edge_t e;

  bool modified_edge = false;
  bool modified_vertex = false;

  modified_vertex = modified_vertex | update_vertex(snd, sndV);
  modified_vertex = modified_vertex | update_vertex(rcv, rcvV);

  // Find the edges associated those vertices.

  bool removed = false;

  edge_map_t::iterator it_rcv = edge_map_.find(rcv);
  if (it_rcv != edge_map_.end() && opposite_vertex(it_rcv->second, rcvV) != sndV) {



    edge_property_[it_rcv->second].clear();
    edge_map_.erase(rcv);
    link_map_.erase(rcv);

    remove_edge(it_rcv->second, g);

    removed = true;
  }

  edge_map_t::iterator it_snd = edge_map_.find(snd);
  if (it_snd != edge_map_.end() && opposite_vertex(it_snd->second, sndV) != rcvV) {

    edge_property_[it_snd->second].clear();
    edge_map_.erase(snd);
    link_map_.erase(snd);


    remove_edge(it_snd->second, g);

    removed = true;

  }



  // There is no link. Create one.
  if ( removed || (it_snd == edge_map_.end() && it_rcv == edge_map_.end()) ) {

    tie(e, modified_edge) = add_edge(sndV, rcvV, g);

    std::cout
      << "LLDP (NEW): "  << e
      << "(" << rcvV << rcv.print() << ")"
      << "(" << sndV << snd.print() << ")" << std::endl;

    weight_property_[e] = NORMAL_WEIGHT;

    edge_property_[e].insert(rcv);
    edge_property_[e].insert(snd);

    edge_map_[rcv] = e;
    edge_map_[snd] = e;

    link_map_[rcv].insert(rcv);
    link_map_[snd].insert(snd);
    build_spanning_tree();
  }

}


void graph::flood_spanning_tree(
    const Openflow_event& ofe,
    const v1::ofp_packet_in& pi) {

  std::cout << "spanning tree flood..." << std::endl;

  const dp_node sw(ofe.dp.id().as_host(), dp_link::OPENFLOW);
  const link_map_t::iterator link_set_it = link_map_.find(sw);

  BOOST_ASSERT(link_set_it != link_map_.end());

  link_map_t::mapped_type link_set = link_set_it->second;

  /*
   * Build a spanning set for the receiving switch.
   */
  std::set<dp_node> spanning_set;

  BOOST_FOREACH(
      const PredecessorMap::value_type& relationship,
      prim_predecessor_impl_) {

    vertex_t child = relationship.first;
    vertex_t parent = relationship.second;

    // Is it a root node?
    if (parent == child) continue;

    dp_node child_node = vertex_property_[child];
    dp_node parent_node = vertex_property_[parent];

    if (sw.datapath_ == parent_node.datapath_) {
      spanning_set.insert(child_node);
    }

    if (sw.datapath_ == child_node.datapath_) {
      spanning_set.insert(parent_node);
    }
  }

  /*
   * Forward the packet along the spanning set.
   */
  link_map_t::mapped_type::iterator link_it;
  for (link_it = link_set.begin();
       link_it != link_set.end();
       std::advance(link_it, 1) ) {

    const dp_link& link = *link_it;

    // Do not send to the incoming port.
    if (link.port_ == pi.in_port()) continue;
    //if (spanning_set.find(link) == spanning_set.end()) continue;

    //std::cout << "flooding along the spanning set on datapath "
    //    << link.datapath_ << " port " << link.port_ << "..."<< std::endl;

    auto po = v1::ofp_packet_out().in_port(pi.in_port()).buffer_id(pi.buffer_id());
    auto ao = v1::ofp_action_output().port(link.port_);
    po.add_action(&ao);

    po.packet(pi.packet());
    ofe.dp.send(&po);
  }

}


/*
 * START HERE 1:
 */
void graph::establish_forward(
    const Openflow_event& ofe,
    const v1::ofp_packet_in& pi) {

  mutex_t::scoped_lock big_lock(big_mutex_);

  using namespace boost;

  vertex_t rcvV, swV;
  edge_t e;

  v1::ofp_match flow;
  flow.from_packet(pi.in_port(), pi.packet());

  /*
   * First construct the required data structures that represent:
   * * sw  -- the switch at which the packet was received.
   * * snd -- the sender.
   * * rvc -- the receiver.
   *
   * FIXME: We are currently doing path discovery using L2, not L3.
   * For now this is fine since there is one-to-one mapping.
   */
  const dp_node sw(ofe.dp.id().as_host(), dp_link::OPENFLOW);
  const dp_node snd(flow.dl_src().hb_long(), dp_node::HOST);
  const dp_node rcv(flow.dl_dst().hb_long(), dp_node::HOST);

  vertex_map_t::iterator srcV_it = vertex_map_.find(snd);
  vertex_map_t::iterator dstV_it = vertex_map_.find(rcv);
  vertex_map_t::iterator swV_it = vertex_map_.find(sw);

  /*
   * Have we ever heard from this host.  If no, just exit.
   */
  if (dstV_it == vertex_map_.end()) {
    std::cout << "unknown destination: " << rcv.print() << std::endl;
    return;
  }



  const eth_header& eth = pull_type<const eth_header>(pi.packet(), 0);
  BOOST_ASSERT_MSG(eth.eth_type == ethernet::IPV6,
      "Omega is implemented on top of IPv6 only.");

  const ip6_hdr& ip6 = pull_type<const ip6_hdr>(pi.packet(), sizeof(eth_header) );
  //const uint8_t next_header = ip6.ip6_ctlun.ip6_un1.ip6_un1_nxt;
  const uint8_t flow_label =
      (ntohl(ip6.ip6_ctlun.ip6_un1.ip6_un1_flow) << 12) >> 12;

  printf("IDR %d is responsible for routing this packet.\n", flow_label);
  printf("%s -> %s\n",
      ip6_addr_str(ip6.ip6_src).c_str(),
      ip6_addr_str(ip6.ip6_dst).c_str());

  BOOST_ASSERT(srcV_it != vertex_map_.end());
  BOOST_ASSERT(dstV_it != vertex_map_.end());

  /*
   * Get the actual vertices.
   */
  rcvV = dstV_it->second;
  swV = swV_it->second;


  if (flow_label == IDR_BGP) {
    bgp(ofe, pi, swV, rcvV);
  } else if (flow_label == IDR_PATHLETS) {
    pathlets(pi, swV, rcvV);
  } else if (flow_label == IDR_DONA) {
    std::cout << "Dona IDR not supported." << std::endl;
  } else if (flow_label == IDR_OPTICAL) {
    std::cout << "Optical IDR not supported." << std::endl;
  } else {
    std::cout << "Unknown IDR." << std::endl;
  }
}


void graph::build_spanning_tree() {

  using namespace boost;

  associative_property_map<PredecessorMap> pm_predecessor(prim_predecessor_impl_);
  associative_property_map<DistanceMap> pm_distance(prim_distance_impl_);

  std::vector < graph_traits < graph_t >::vertex_descriptor >
    p(num_vertices(g));

  prim_minimum_spanning_tree(g,
      pm_predecessor
      );
}


/*
 * START HERE 1:
 */
void graph::establish(
    const Openflow_event& ofe,
    const v1::ofp_packet_in& pi) {

  mutex_t::scoped_lock big_lock(big_mutex_);

  using namespace boost;

  vertex_t sndV, rcvV;
  edge_t e;

  v1::ofp_match flow;
  flow.from_packet(pi.in_port(), pi.packet());
  /*
   * First construct the required data structures that represent:
   * * sw  -- the switch at which the packet was received.
   * * snd -- the sender.
   * * rvc -- the receiver.
   *
   * FIXME: We are currently doing path discovery using L2, not L3.
   * For now this is fine since there is one-to-one mapping.
   */
  const dp_node snd(flow.dl_src().hb_long(), dp_node::HOST);
  const dp_node rcv(flow.dl_dst().hb_long(), dp_node::HOST);

  vertex_map_t::iterator srcV_it = vertex_map_.find(snd);
  vertex_map_t::iterator dstV_it = vertex_map_.find(rcv);


  /*
   * Have we ever heard from this host.  If no, just exit.
   */
  if (dstV_it == vertex_map_.end()) {
    std::cout << "unknown destination: " << rcv.print() << std::endl;
    return;
  }

  BOOST_ASSERT(srcV_it != vertex_map_.end());
  BOOST_ASSERT(dstV_it != vertex_map_.end());


  /*
   * Get the actual vertices.
   */
  sndV = srcV_it->second;
  rcvV = dstV_it->second;

   /*
    * START HERE 2: Figure out where the destination host is.
    *
    * This is where different ISMs will reside.
    */
   PredecessorMap predecessor_map_impl;
   DistanceMap distance_map_impl;

   associative_property_map<PredecessorMap> pm_predecessor(predecessor_map_impl);
   associative_property_map<DistanceMap> pm_distance(distance_map_impl);

   dijkstra_shortest_paths(g, sndV,
       predecessor_map(pm_predecessor).
       distance_map(pm_distance)
       );


   /*
    * This part of the code should never fail.  If it does, there is
    * something wrong with the code.
    *
    * All this does is translates the obtained path to a meaningful
    * representation.
    */
   std::deque<dp_link> link_queue, ids_link_queue;
   std::deque<vertex_t> vertex_queue, ids_vertex_queue;

   /*
    * Aggregate map is:
    *
    * (A switch in the path) -> (input port, output port)
    */
   aggregate_map_t aggregate_map;

   /*
    * Don't worry about the link_queue_vercor. It is only used for
    * multi-path routing.
    */
   std::vector< std::deque<dp_link> > link_queue_vercor;

   if(dstV_it != vertex_map_.end()) {

     bool found = find_path(sndV, rcvV, pm_predecessor, link_queue, vertex_queue);
     if (!found) {
       std::cout << "unable to construct the path!" << std::endl;
       return;
     }

     if (link_queue.empty()) {
       std::cout << "find_path returned an empty queue!" << std::endl;
       return;
     }

     BOOST_ASSERT(!link_queue.empty());

     link_queue.pop_front();
     link_queue.pop_back();

     link_queue_vercor.push_back(link_queue);


   }

   BOOST_FOREACH(auto& link, link_queue) {
     printf("%x:%d\n", link.datapath_, link.port_);
   }

   /*
    * Here you can simply output the packet.
    *
    * TODO: Clean up this function.
    */
   aggregate_flows(ofe, pi, link_queue, aggregate_map);
}


/*
 * The function that does the actual translation from the abstract path
 * to the concrete path.
 */
bool graph::find_path(
    vertex_t srcV, vertex_t dstV,
    boost::associative_property_map<PredecessorMap>& pm_predecessor,
    std::deque<dp_link>& link_queue,
    std::deque<vertex_t>& vertex_queue) {

  using namespace boost;

  edge_iterator_t out_start, out_end;
  edge_t tmpE;
  vertex_t preV;

  vertex_queue.push_back(dstV);
  while (dstV != srcV) {
    preV = pm_predecessor[dstV];

    if(preV == dstV) return false;

    dstV = preV;
    vertex_queue.push_back(dstV);
  }

  BOOST_ASSERT(!vertex_queue.empty());

  vertex_t perV = vertex_queue.back();
  vertex_queue.pop_back();

  while (!vertex_queue.empty()) {
    dstV = vertex_queue.back();

    tie(out_start, out_end) = out_edges(dstV, g);

    for (; (out_start != out_end); out_start++) {
      tmpE = *out_start;

      if (opposite_vertex(tmpE, dstV) != perV) continue;

      const std::set<dp_link>& paths = edge_property_[tmpE];

      BOOST_ASSERT(paths.size() == 2);
      dp_link in, out;

      tie(in, out) = ordering(perV, paths);
      link_queue.push_back(in);
      link_queue.push_back(out);
    }

    vertex_queue.pop_back();
    perV = dstV;
  }

  return true;
}


/*
 * Skip to minject() function.  This is some distributed IDS relict.
 */
void graph::aggregate_flows(
    const Openflow_event& ofe,
    const v1::ofp_packet_in& pi,
    const std::deque<dp_link> link_queue,
    aggregate_map_t& aggregate_map) {


  const uint32_t label = get_random_uint32_t();

  BOOST_ASSERT(link_queue.size() % 2 == 0);

  size_t count = 1;

  for(auto link_it = link_queue.begin(); link_it != link_queue.end();) {

    dp_link first(*link_it);
    std::advance(link_it, 1);
    dp_link second(*link_it);
    std::advance(link_it, 1);

    link_pair_t p(first, second);
    std::set<link_pair_t> s;
    s.insert(p);

    if (count == 1) {
      minject(ofe, pi, s, ActionType::PUSH,label);
    } else if (count == (link_queue.size()/2)) {
      minject(ofe, pi, s, ActionType::POP, label);
    } else {
      minject(ofe, pi, s, ActionType::FWD, label);
    }

    count++;
  }
}


/*
 * START HERE 3: This is probably the most importatnt function.
 *
 * Given a map { SWITCH -> (IN PORT, OUT PORT) }, set up a flow
 * entry set that will do the following:
 *
 * On any packet that is received on IN port...
 * and is of the Ethernet type 0x86DD...
 * and the destination address is DST...
 * and the flow label is of value IDR (currently removed due to debugging)...
 *
 * output it to port OUT.
 *
 * If you don't want to install any rules (i.e. just forward the packets),
 * so,[;y call send_openflow_packet() using pi.datapath_id (receiving switch)
 * and the correct output port.
 */
void graph::minject(
    const Openflow_event& ofe,
    const v1::ofp_packet_in& pi,
    const std::set<link_pair_t>& flow_set,
    const ActionType action_type,
    const uint32_t label) {

  typedef std::set<uint16_t> port_set_t;
  port_set_t in_set, out_set;

  dp_link dp;

  BOOST_FOREACH(const aggregate_map_t::mapped_type::value_type& v, flow_set) {
    dp = v.first;

    in_set.insert(v.first.port_);
    out_set.insert(v.second.port_);
  }

  BOOST_ASSERT(in_set.size() >= 1);
  BOOST_ASSERT(out_set.size() >= 1);

  boost::shared_array<uint8_t> raw_of;

  auto i = device_map.find(dp.datapath_);
  BOOST_ASSERT(i != device_map.end());

  if(action_type == ActionType::FWD) {
    const size_t size = detail::forward_mpls(pi, raw_of, in_set, out_set, label);
    i->second->send_raw((const char*) raw_of.get(), size);
  } else if(action_type == ActionType::PUSH) {
    const size_t size = detail::push_mpls(pi, raw_of, in_set, out_set, label);
    i->second->send_raw((const char*) raw_of.get(), size);
  } else if(action_type == ActionType::POP) {
    const size_t size = detail::pop_mpls(pi, raw_of, in_set, out_set, label);
    i->second->send_raw((const char*) raw_of.get(), size);
  }
}
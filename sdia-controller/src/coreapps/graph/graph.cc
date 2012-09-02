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
#include <boost/graph/prim_minimum_spanning_tree.hpp>
#include <boost/range.hpp>

#include "helper.cc"
#include "lldp.cc"
#include "events.cc"
#include "end-host.cc"
#include "interfaces.cc"
#include "commands.hh"


using namespace vigil;
using namespace openflow;


/*
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
   * When you want to output the packet that was sent to you (the controller),
   * you _have_to refer to its buffer ID.
   */

  /*
   * Pretty useless in our case, since it is parses it as IPv4,
   * so feel free to ignore it.
   */
  v1::ofp_match flow;
  flow.from_packet(pi.in_port(), pi.packet());

  if (flow.dl_type() == OFP_DL_TYPE_NOT_ETH_TYPE) {
    return STOP;
  }

  /*
   * Discovery protocol.
   *
   * Constructs the non end-host part of the topology.
   */
  if (flow.dl_type() == ntohs(ethernet::LLDP)) {
    neighbor_discovery(ofe, pi);
    return STOP;
  }

  /* Handle only IP6 packets. */
  if (flow.dl_type() != ntohs(ethernet::IPV6)) {
    return STOP;
  }



  vertex_t srcV;
  if (is_unicast(flow.dl_src())) {
    srcV = collect(ofe, pi);
  }

  const ip6_hdr& ip6 = pull_type<ip6_hdr>( pi.packet(), sizeof(eth_header) );
  const uint32_t flow_label = get_flow(ip6);
  printf("IDR %d is responsible for routing this packet.\n", flow_label);

  if (flow.dl_dst().is_zero()) {
    update_receive(ofe, pi);
    return STOP;
  }

  /*
   * Collect end-host L2 and L3 information.  Constructs the end-host
   * part of the topology.
   */
  /*
   * This is the part that does the actual routing.
   */
  if (is_unicast(flow)) {

    const uint32_t label = get_random<uint32_t>();
    auto p = std::make_pair(ip6.ip6_src, ip6.ip6_dst);
    labeling_[label] = p;

    distribute_packet(pi, label, srcV);
  } else {
    /*
     * Otherwise, just flood.
     *
     * TODO: Flood only on links that constitute the apsnning tree.
     */
    flood_spanning_tree(ofe, pi);
  }
  return STOP;
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



  dp_link snd = extract_lldp(pi.packet());

  dp_link rcv(
      ofe.dp.id().as_host(),
      pi.in_port(),
      domain_id_,
      dp_link::OPENFLOW);


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
    remove_edge(it_rcv->second, g);
    edge_map_.erase(rcv);
    link_map_.erase(rcv);
    removed = true;
  }

  edge_map_t::iterator it_snd = edge_map_.find(snd);
  if (it_snd != edge_map_.end() && opposite_vertex(it_snd->second, sndV) != rcvV) {

    edge_property_[it_snd->second].clear();
    remove_edge(it_snd->second, g);
    edge_map_.erase(snd);
    link_map_.erase(snd);
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

  const dp_node sw(ofe.dp.id().as_host(), domain_id_, dp_link::OPENFLOW);
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

    auto po = v1::ofp_packet_out().in_port(pi.in_port()).buffer_id(pi.buffer_id());
    auto ao = v1::ofp_action_output().port(link.port_);
    po.add_action(&ao);

    po.packet(pi.packet());
    ofe.dp.send(&po);
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

void graph::establish(
    const uint32_t label,
    const std::string tlv_match,
    const vertex_t sndV,
    const vertex_t midV,
    const vertex_t rcvV) {

  std::cout << "routing through a middlebox" << std::endl;

  std::deque<dp_link> link_queue0;
  establish_impl(label, tlv_match, sndV, midV, link_queue0);

  if (link_queue0.empty()) {
    std::cout << "find_path returned an empty queue!" << std::endl;
    return;
  }

  BOOST_ASSERT(!link_queue0.empty());

  link_queue0.pop_front();
  link_queue0.pop_back();



  std::deque<dp_link> link_queue1;
  establish_impl(label, tlv_match, midV, rcvV, link_queue1);

  if (link_queue1.empty()) {
    std::cout << "find_path returned an empty queue!" << std::endl;
    return;
  }

  BOOST_ASSERT(!link_queue1.empty());

  link_queue1.pop_front();
  link_queue1.pop_back();

  link_queue0.insert(
      link_queue0.end(),
      link_queue1.begin(),
      link_queue1.end());

  BOOST_FOREACH(auto& link, link_queue0) {
    printf("%x:%d\n", link.datapath_, link.port_);
  }

  aggregate_map_t aggregate_map;
  aggregate_flows(label, tlv_match,  link_queue0, aggregate_map);
}



void graph::establish(
    const uint32_t label,
    const std::string tlv_match,
    const vertex_t sndV,
    const vertex_t rcvV) {

  std::deque<dp_link> link_queue;
  establish_impl(label, tlv_match, sndV, rcvV, link_queue);

  if (link_queue.empty()) {
    std::cout << "find_path returned an empty queue!" << std::endl;
    return;
  }

  BOOST_ASSERT(!link_queue.empty());

  link_queue.pop_front();
  link_queue.pop_back();


  BOOST_FOREACH(auto& link, link_queue) {
    printf("%x:%d\n", link.datapath_, link.port_);
  }

  aggregate_map_t aggregate_map;
  aggregate_flows(label, tlv_match, link_queue, aggregate_map);
}



void graph::establish_impl(
    const uint32_t label,
    const std::string tlv_match,
    const vertex_t sndV,
    const vertex_t rcvV,
    std::deque<dp_link>& link_queue) {

  mutex_t::scoped_lock big_lock(big_mutex_);

  using namespace boost;

  //vertex_t sndV, rcvV;
  edge_t e;

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
   std::deque<vertex_t> vertex_queue;

   bool found = find_path(sndV, rcvV, pm_predecessor,
       link_queue, vertex_queue);
   if (!found) {
     std::cout << "unable to construct the path!" << std::endl;
     return;
   }
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
    const uint32_t label,
    const std::string tlv_match,
    const std::deque<dp_link> link_queue,
    aggregate_map_t& aggregate_map) {

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
      minject(s, ActionType::PUSH,label, tlv_match);
    } else if (count == (link_queue.size()/2)) {
      minject(s, ActionType::POP, label, tlv_match);
    } else {
      minject(s, ActionType::FWD, label, tlv_match);
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
    const std::set<link_pair_t>& flow_set,
    const ActionType action_type,
    const uint32_t label,
    const std::string tlv_match) {

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
    const size_t size = detail::forward_mpls(raw_of, in_set, out_set, label);
    i->second->send_raw((const char*) raw_of.get(), size);
  } else if(action_type == ActionType::PUSH) {
    struct in6_addr address = labeling_[label].second;
    const size_t size = detail::push_mpls(address, raw_of, in_set, out_set, label, tlv_match);
    i->second->send_raw((const char*) raw_of.get(), size);
  } else if(action_type == ActionType::POP) {
    const size_t size = detail::pop_mpls(raw_of, in_set, out_set, label);
    i->second->send_raw((const char*) raw_of.get(), size);
  }
}

/*
 * graph.hh
 *
 *  Created on: 2010-05-10
 *      Author: vjeko
 */

#ifndef GRAPH_HH_
#define GRAPH_HH_

#include <boost/bind.hpp>
#include <boost/foreach.hpp>
#include <boost/shared_array.hpp>
#include <cstring>
#include <netinet/in.h>
#include <stdexcept>
#include <stdint.h>

#include "misc.hh"
#include "assert.hh"
#include "component.hh"
#include "fnv_hash.hh"
#include "hash_set.hh"
#include "vlog.hh"
#include "string.hh"

#include "openflow/openflow-event.hh"
#include "openflow/openflow-datapath-join-event.hh"
#include "openflow/openflow-datapath-leave-event.hh"

#include "openflow/openflow.h"

#include "netinet++/ethernetaddr.hh"
#include "netinet++/ethernet.hh"

#include <iostream>                  // for std::cout
#include <utility>                   // for std::pair
#include <algorithm>                 // for std::for_each
#include <set>

#include <boost/graph/graph_traits.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/dijkstra_shortest_paths.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/graph/graphml.hpp>

#include <boost/thread/thread.hpp>
#include <tbb/mutex.h>

#include <deque>
#include <vector>
#include <boost/bind/bind.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/asio/buffer.hpp>

#include "packets.h"
#include "protobuf/interface.pb.h"
#include <netinet/ip6.h>

using namespace vigil;
using namespace openflow;

using boost::shared_ptr;

class graph: public Component {
public:

  enum WeightType {
    NORMAL_WEIGHT = 1,
  };

  enum ActionType {
    FWD,
    PUSH,
    POP
  };

  // Create a typedef for the Graph type.
  typedef boost::adjacency_list<boost::vecS, boost::vecS,
      boost::undirectedS,
      boost::property<boost::vertex_name_t, dp_node>,
      boost::property<boost::edge_name_t, std::set<dp_link>,
      boost::property<boost::edge_weight_t, int>
  > > graph_t;

  typedef boost::property_map<graph_t, boost::vertex_name_t>::type vertex_property_t;
  typedef boost::property_map<graph_t, boost::edge_name_t>::type edge_property_t;
  typedef boost::property_map<graph_t, boost::edge_weight_t>::type weight_property_t;

  typedef boost::graph_traits<graph_t>::vertex_descriptor vertex_t;
  typedef boost::graph_traits<graph_t>::edge_descriptor edge_t;
  typedef boost::graph_traits<graph_t>::out_edge_iterator edge_iterator_t;

  typedef std::pair<dp_link, dp_link> link_pair_t;

  typedef std::map<dp_link, edge_t> edge_map_t;
  typedef std::map<dp_node, vertex_t> vertex_map_t;
  typedef std::map<dp_node, std::set<link_pair_t> > aggregate_map_t;
  typedef std::map<dp_node, std::set<dp_link> > link_map_t;
  typedef std::map<dp_node, ActionType> action_map_t;

  typedef int weight_t;
  typedef std::map<vertex_t, vertex_t>  PredecessorMap;
  typedef std::map<vertex_t, weight_t>  DistanceMap;

  typedef std::map<uint64_t, std::vector<v1::ofp_phy_port> > join_event_map_t;
  typedef std::map<uint64_t, boost::shared_ptr<Openflow_datapath>  > join_event_map2_t;

  graph(const Component_context* c) :
    Component(c), graph_log("graph") {

    domain_id_ = get_random<uint64_t>();
    vertex_property_ = boost::get(boost::vertex_name, g);
    edge_property_ = boost::get(boost::edge_name, g);
    weight_property_ = boost::get(boost::edge_weight, g);
  }

  void configure();
  void install();

  Disposition handle(const Event&);
  Disposition join(const Event&);

  template<class F>
  vertex_t collect(
      const Openflow_event& ofe,
      const v1::ofp_packet_in& pi);

  void neighbor_discovery(
      const Openflow_event& ofe,
      const v1::ofp_packet_in& pi);

  void establish(
      const uint32_t label,
      const std::string tlv_match,
      const vertex_t sndV,
      const vertex_t rcvV);

  void establish(
      const uint32_t label,
      const std::string tlv_match,
      const vertex_t sndV,
      const vertex_t midV,
      const vertex_t rcvV);

  void establish_impl(
      const uint32_t label,
      const std::string tlv_match,
      const vertex_t sndV,
      const vertex_t rcvV,
      std::deque<dp_link>& link_queue);

  bool update_edge(const dp_node src, const dp_node dst);
  bool update_vertex(const dp_node id, vertex_t& v);

  template<typename Buffer>
  void send_blob(
      Buffer buffer,
      boost::shared_ptr<Openflow_datapath> dp,
      const uint16_t port_num);

  void update_receive(
      const Openflow_event& ofe,
      const v1::ofp_packet_in& pi);

  void send_lldp();
  dp_link extract_lldp(
      const boost::asio::const_buffer& buffer);

  void write_topology();
  void ism_interface ();

  void build_spanning_tree();
  void flood_spanning_tree(
      const Openflow_event& ofe,
      const v1::ofp_packet_in& pi);

  bool find_path(
      vertex_t srcV, vertex_t dstV,
      boost::associative_property_map<PredecessorMap>&  pm_predecessor,
      std::deque<dp_link>& link_queue,
      std::deque<vertex_t>& vertex_queue);

  void aggregate_flows(
      const uint32_t label,
      const std::string tlv_match,
      const std::deque<dp_link> link_queue,
      aggregate_map_t& aggregate_map);

  void minject(
      const aggregate_map_t::mapped_type& flow_set,
      const ActionType action_type,
      const uint32_t label,
      const std::string tlv_match);

  const size_t normal_forward(
      const v1::ofp_packet_in& pi,
      boost::shared_array<uint8_t>& raw_of,
      std::set<uint16_t> in_set,
      std::set<uint16_t> out_set
      );

  vertex_t opposite_vertex(edge_t e, vertex_t swV);

  void distribute_topology(std::string s);
  void distribute_packet(
      const v1::ofp_packet_in& pi,
      const uint32_t label,
      const vertex_t srcV);

  template<typename V, typename Q>
  std::pair<typename Q::key_type, typename Q::key_type> ordering(V v, Q q);

  graph_t  g;
  uint32_t domain_id_;

  edge_map_t   edge_map_;
  vertex_map_t vertex_map_;
  link_map_t   link_map_;

  vertex_property_t vertex_property_;
  edge_property_t   edge_property_;
  weight_property_t weight_property_;

  dp_node::transaction_t get_transaction_id();

  typedef tbb::mutex mutex_t;
  typedef std::map<dp_link, mutex_t> lock_map_t;

  //tbb::task_group tg_;
  boost::thread_group tg_;
  mutex_t big_mutex_;
  mutex_t send_mutex_;

  PredecessorMap prim_predecessor_impl_;
  DistanceMap    prim_distance_impl_;

  join_event_map2_t device_map;

  Vlog_module graph_log;
  shared_ptr<server> server_;

  std::map< int32_t, std::pair<in6_addr, in6_addr> > labeling_;

private:
};

REGISTER_COMPONENT(Simple_component_factory<graph>, graph);


#endif /* GRAPH_HH_ */

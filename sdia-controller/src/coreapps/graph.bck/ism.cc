#include "graph.hh"

#include <boost/graph/prim_minimum_spanning_tree.hpp>



void graph::bgp(
    const Openflow_event& ofe,
    const v1::ofp_packet_in& pi,
    const graph::vertex_t swV,
    const graph::vertex_t rcvV) {


  using namespace boost;

  graph::PredecessorMap predecessor_map_impl;
  graph::DistanceMap distance_map_impl;

  associative_property_map<graph::PredecessorMap> pm_predecessor(predecessor_map_impl);
  associative_property_map<graph::DistanceMap> pm_distance(distance_map_impl);

  boost::dijkstra_shortest_paths(graph::g, swV,
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
  std::deque<graph::vertex_t> vertex_queue, ids_vertex_queue;

  /*
   * Aggregate map is:
   *
   * (A switch in the path) -> (input port, output port)
   */
  graph::aggregate_map_t aggregate_map;

  /*
   * Don't worry about the link_queue_vercor. It is only used for
   * multi-path routing.
   */
  std::vector< std::deque<dp_link> > link_queue_vercor;

  bool found = graph::find_path(swV, rcvV, pm_predecessor, link_queue, vertex_queue);
  if (!found) {
    std::cout << "unable to construct the path!" << std::endl;
    return;
  }

  if (link_queue.empty()) {
    std::cout << "find_path returned an empty queue!" << std::endl;
    return;
  }

  BOOST_ASSERT(!link_queue.empty());

  auto& po = v1::ofp_packet_out().in_port(pi.in_port()).buffer_id(pi.buffer_id());
  auto& ao = v1::ofp_action_output().port(link_queue.front().port_);
  po.add_action(&ao);
  ofe.dp.send(&po);

 //send_openflow_packet(pi.datapath_id, pi.buffer_id,
  //    link_queue.front().port_, pi.in_port, true);
}



void graph::pathlets(
    const v1::ofp_packet_in& pi,
    const graph::vertex_t swV,
    const graph::vertex_t rcvV) {


  using namespace boost;

  graph::PredecessorMap predecessor_map_impl;
  graph::DistanceMap distance_map_impl;

  associative_property_map<graph::PredecessorMap> pm_predecessor(predecessor_map_impl);
  associative_property_map<graph::DistanceMap> pm_distance(distance_map_impl);

  boost::dijkstra_shortest_paths(graph::g, swV,
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
  std::deque<graph::vertex_t> vertex_queue, ids_vertex_queue;

  /*
   * Aggregate map is:
   *
   * (A switch in the path) -> (input port, output port)
   */
  graph::aggregate_map_t aggregate_map;

  /*
   * Don't worry about the link_queue_vercor. It is only used for
   * multi-path routing.
   */
  std::vector< std::deque<dp_link> > link_queue_vercor;

  bool found = graph::find_path(swV, rcvV, pm_predecessor, link_queue, vertex_queue);
  if (!found) {
    std::cout << "unable to construct the path!" << std::endl;
    return;
  }

  if (link_queue.empty()) {
    std::cout << "find_path returned an empty queue!" << std::endl;
    return;
  }

  BOOST_ASSERT(!link_queue.empty());

  //send_openflow_packet(pi.datapath_id, pi.buffer_id,
  //    link_queue.front().port_, pi.in_port, true);
}



void graph::dona(
    const v1::ofp_packet_in& pi,
    const graph::vertex_t swV,
    const graph::vertex_t rcvV) {

}

#include "graph.hh"
#include <boost/asio.hpp>

/*
 * Output the current topology to a dot file.
 */
void graph::write_topology() {

  sleep(5);

  while(true) {
    std::ofstream dot_file("topology.dot");
    boost::write_graphviz(dot_file, g, label_writer<vertex_property_t>(vertex_property_));
    dot_file.close();

    sleep(2);
  }
}

template<class Type>
const Type& pull_type(
		const boost::asio::const_buffer& buffer,
		size_t size) {
	const char* p = boost::asio::buffer_cast<const char*>(buffer);
	const Type* t = (const Type*) (p + size);
	return *t;
}

bool is_unicast(const vigil::ethernetaddr& e) {

  if ((!e.is_broadcast()) && (!e.is_multicast())) return true;
  return false;
}

bool is_unicast(const v1::ofp_match& flow) {
  if (is_unicast(flow.dl_src()) && is_unicast(flow.dl_dst())) return true;
  return false;
}


dp_node::transaction_t graph::get_transaction_id() {
  return ++transaction_id_;
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

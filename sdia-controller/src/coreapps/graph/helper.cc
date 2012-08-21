#include "graph.hh"

#include <boost/asio.hpp>


template<typename V, typename Q>
std::pair<typename Q::key_type, typename Q::key_type> graph::ordering(V v, Q q) {

  typename Q::key_type in, out;
  typename Q::iterator it = q.begin();

  if (vertex_property_[v].get_datapath() == it->get_datapath()) {
    in = *it; out = *(++it);
  } else {
    out = *it; in = *(++it);
  }

  return std::make_pair(in, out);
}



void graph::distribute_packet(
    const v1::ofp_packet_in& pi,
    const uint32_t label,
    const vertex_t srcV) {

  RPC rpc;
  rpc.set_type(RPC::PacketInRequest);

  PacketInRequest* packet = rpc.MutableExtension(PacketInRequest::msg);

  const auto size = boost::asio::buffer_size(pi.packet());
  const char* p = boost::asio::buffer_cast<const char*>(pi.packet());
  std::string s(p, size);
  packet->set_packet(s);
  packet->set_srcv(srcV);
  packet->set_cookie(label);

  BOOST_FOREACH(auto& session, server_->sessions_) {
    session->write(rpc);
  }
}



void graph::distribute_topology(std::string s) {
  RPC rpc;
  rpc.set_type(RPC::Topology);

  Topology* pr = rpc.MutableExtension(Topology::msg);
  pr->set_dot(s);

  BOOST_FOREACH(auto& session, server_->sessions_) {
    session->write(rpc);
  }
}

/*
 * Output the current topology to a dot file.
 */
void graph::write_topology() {

  sleep(1);

  while(true) {

    std::ostringstream stream;
    boost::write_graphviz(stream, g, label_writer<vertex_property_t>(vertex_property_));
    distribute_topology(stream.str());

    sleep(2);
  }
}

template<class Type>
Type& pull_type(
    uint8_t* p,
    size_t offset) {
  Type* t = (Type*) (p + offset);
  return *t;
}

template<class Type>
const Type& pull_type(
    const uint8_t* p,
    size_t offset) {
  const Type* t = (const Type*) (p + offset);
  return *t;
}

template<class Type>
const Type& pull_type(
		const boost::asio::const_buffer& buffer,
		size_t offset) {
	const uint8_t* p = boost::asio::buffer_cast<const uint8_t*>(buffer);
	return pull_type<Type>(p, offset);
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
  static uint64_t transaction_id;
  return ++transaction_id;
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

#include <ctype.h>
#include <stdio.h>

void hexdump(const void *ptr, int buflen) {
  unsigned char *buf = (unsigned char*)ptr;
  int i, j;
  for (i=0; i<buflen; i+=16) {
    printf("%06x: ", i);
    for (j=0; j<16; j++)
      if (i+j < buflen)
        printf("%02x ", buf[i+j]);
      else
        printf("   ");
    printf(" ");
    for (j=0; j<16; j++)
      if (i+j < buflen)
        printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
    printf("\n");
  }
}

static const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";


static inline bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
  std::string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';

  }

  return ret;

}

std::string base64_decode(std::string const& encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  std::string ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret += char_array_3[i];
      i = 0;
    }
  }

  if (i) {
    for (j = i; j <4; j++)
      char_array_4[j] = 0;

    for (j = 0; j <4; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
  }

  return ret;
}


/*
ovs_be32 nx_eth = htonl(NXM_OF_ETH_TYPE);
ovs_be16 eth_type = htons(0x86dd);

memcpy(raw_of.get() + sizeof(nx_flow_mod),
    &nx_eth, sizeof(ovs_be32));
memcpy(raw_of.get() + sizeof(nx_flow_mod) + sizeof(ovs_be32),
    &eth_type, sizeof(uint16_t));

ovs_be32 nx_header = htonl(NXM_NX_IPV6_DST);

memcpy(raw_of.get() + sizeof(nx_flow_mod) +
    sizeof(ovs_be32) + sizeof(ovs_be16),
    &nx_header, sizeof(ovs_be32));
memcpy(raw_of.get() + sizeof(nx_flow_mod) +
    sizeof(ovs_be32) + sizeof(ovs_be16) + sizeof(uint32_t),
    &address, sizeof(uint64_t)*2);
*/

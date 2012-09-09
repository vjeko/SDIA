/*
 * commands.hh
 *
 *  Created on: Jul 16, 2012
 *      Author: vjeko
 */

#ifndef COMMANDS_HH_
#define COMMANDS_HH_

#include "openflow/openflow-event.hh"
#include "openflow/nicira-ext.h"

#include "packets.h"
#include <netinet/ip6.h>

namespace detail {

using namespace vigil;
using namespace openflow;


const size_t push_mpls(
    struct in6_addr address,
    boost::shared_array<uint8_t>& raw_of,
    std::set<uint16_t> in_port,
    std::set<uint16_t> out_set,
    const uint32_t l,
    const std::string tlv_match,
    const std::string action
    ) {

  const size_t tlv_size = tlv_match.size();

  const size_t tlv_size_aligned =
      tlv_size + (8 - (tlv_size % 8)) % 8;

  const size_t size =
      sizeof(nx_flow_mod) +
      action.size() +
      sizeof(nx_action_push_mpls) +
      sizeof(nx_action_mpls_label) +
      sizeof(ofp_action_output) +
      tlv_size_aligned;


  raw_of = boost::shared_array<uint8_t>(new uint8_t[size]);
  auto* ofm = (nx_flow_mod*) raw_of.get();

  memset(raw_of.get(), 0, size);

  ofm->nxh.header.version = v1::OFP_VERSION;
  ofm->nxh.header.type = OFPT_VENDOR;
  ofm->nxh.header.length = htons(size);

  ofm->nxh.vendor = htonl(NX_VENDOR_ID);
  ofm->nxh.subtype = htonl(NXT_FLOW_MOD);

  ofm->cookie = 0;
  ofm->command = htons(OFPFC_ADD);
  ofm->buffer_id = htonl(-1);
  ofm->idle_timeout = htons(5);
  ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
  ofm->priority = htons(OFP_DEFAULT_PRIORITY);
  ofm->flags = htons(0);
  ofm->match_len = htons(tlv_size);

  memcpy(raw_of.get() + sizeof(nx_flow_mod),
      tlv_match.c_str(), tlv_match.size());

  memcpy(raw_of.get() + sizeof(nx_flow_mod) + tlv_size_aligned,
      action.c_str(), action.size());

  std::cout << "Match size: " << tlv_match.size() << std::endl;
  std::cout << "Action size: " << action.size() << std::endl;

  //hexdump(raw_of.get() + sizeof(nx_flow_mod), tlv_match.size());
  hexdump(raw_of.get() + sizeof(nx_flow_mod) + tlv_size_aligned, action.size());

  nx_action_push_mpls& action_push = *(
   (nx_action_push_mpls*) (raw_of.get() +
       sizeof(nx_flow_mod) + tlv_size_aligned + action.size() )
   );

   memset(&action_push, 0, sizeof(nx_action_push_mpls));
   action_push.type = htons(0xffff);
   action_push.len = htons( sizeof(struct nx_action_push_mpls) );
   action_push.vendor = htonl(NX_VENDOR_ID);
   action_push.subtype =  htons(NXAST_PUSH_MPLS);
   action_push.ethertype = htons(0x8847);

   nx_action_mpls_label& label_action = *((nx_action_mpls_label*) (raw_of.get()
       + sizeof(nx_flow_mod) + tlv_size_aligned + action.size() +
       sizeof(nx_action_push_mpls)));

   memset(&label_action, 0, sizeof(nx_action_mpls_label));
   label_action.type = htons(0xffff);
   label_action.len = htons( sizeof(struct nx_action_mpls_label) );
   label_action.vendor = htonl(NX_VENDOR_ID);
   label_action.subtype =  htons(NXAST_SET_MPLS_LABEL);
   label_action.mpls_label = htonl(0x000FFFFF & l);

  ofp_action_output& action_output = *((ofp_action_output*) (
      raw_of.get() + sizeof(nx_flow_mod) + tlv_size_aligned + action.size() +
      sizeof(nx_action_push_mpls) + sizeof(nx_action_mpls_label)
      ));

  auto out_it = out_set.begin();

  memset(&action_output, 0, sizeof(ofp_action_output));
  action_output.type = htons(OFPAT10_OUTPUT);
  action_output.len = htons(sizeof(ofp_action_output));
  action_output.port = htons(*out_it);
  action_output.max_len = htons(0);

  return size;
}




const size_t pop_mpls(
    boost::shared_array<uint8_t>& raw_of,
    std::set<uint16_t> in_port,
    std::set<uint16_t> out_set,
    uint32_t l
    ) {

  const size_t tlv_size =
      ( sizeof(ovs_be32) + sizeof(ovs_be16) ) +
      ( sizeof(ovs_be32) + sizeof(ovs_be32) ) ;

  const size_t tlv_size_aligned =
      tlv_size + (8 - (tlv_size % 8)) % 8;

  const size_t size =
      sizeof(nx_flow_mod) +
      sizeof(nx_action_pop_mpls) +
      sizeof(ofp_action_output) +
      tlv_size_aligned;

  nx_flow_mod* ofm;

  raw_of = boost::shared_array<uint8_t>(new uint8_t[size]);
  ofm = (nx_flow_mod*) raw_of.get();
  memset(raw_of.get(), 0, size);

  ofm->nxh.header.version = v1::OFP_VERSION;
  ofm->nxh.header.type = OFPT_VENDOR;
  ofm->nxh.header.length = htons(size);

  ofm->nxh.vendor = htonl(NX_VENDOR_ID);
  ofm->nxh.subtype = htonl(NXT_FLOW_MOD);

  ofm->cookie = 0;
  ofm->command = htons(OFPFC_ADD);
  ofm->buffer_id = htonl(-1);
  ofm->idle_timeout = htons(5);
  ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
  ofm->priority = htons(OFP_DEFAULT_PRIORITY);
  ofm->flags = htons(0);
  ofm->match_len = htons(tlv_size);

  ovs_be32 eth_match = htonl(NXM_OF_ETH_TYPE);
  ovs_be16 eth_type = htons(0x8847);

  memcpy(raw_of.get() + sizeof(nx_flow_mod),
      &eth_match, sizeof(ovs_be32));
  memcpy(raw_of.get() + sizeof(nx_flow_mod) + sizeof(ovs_be32),
      &eth_type, sizeof(uint16_t));


  ovs_be32 label_match = htonl(NXM_NX_MPLS_LABEL);
  ovs_be32 label_value = htonl(0x000FFFFF & l);

  memcpy(raw_of.get() + sizeof(nx_flow_mod)
      + sizeof(ovs_be32) + sizeof(uint16_t),
      &label_match, sizeof(uint32_t));
  memcpy(raw_of.get() + sizeof(nx_flow_mod)
      + sizeof(ovs_be32) + sizeof(uint16_t) + sizeof(ovs_be32),
      &label_value, sizeof(uint32_t));

  nx_action_pop_mpls& action_pop = *(
   (nx_action_pop_mpls*)
   (raw_of.get() + sizeof(nx_flow_mod) + tlv_size_aligned )
  );

  memset(&action_pop, 0, sizeof(nx_action_pop_mpls));
  action_pop.type = htons(0xffff);
  action_pop.len = htons( sizeof(struct nx_action_pop_mpls) );
  action_pop.vendor = htonl(NX_VENDOR_ID);
  action_pop.subtype =  htons(NXAST_POP_MPLS);
  action_pop.ethertype = htons(0x86DD);

  std::cout << "NXAST_POP_MPLS: " << NXAST_POP_MPLS << std::endl;

  ofp_action_output& action_output = *((ofp_action_output*) (raw_of.get()
      + sizeof(nx_flow_mod) + sizeof(nx_action_pop_mpls) + tlv_size_aligned));

  auto out_it = out_set.begin();

  memset(&action_output, 0, sizeof(ofp_action_output));
  action_output.type = htons(OFPAT10_OUTPUT);
  action_output.len = htons(sizeof(ofp_action_output));
  action_output.port = htons(*out_it);
  action_output.max_len = htons(0);

  return size;
}



const size_t forward_mpls(
    boost::shared_array<uint8_t>& raw_of,
    std::set<uint16_t> in_port,
    std::set<uint16_t> out_set,
    uint32_t l
    ) {

  const size_t tlv_size =
      ( sizeof(ovs_be32) + sizeof(ovs_be16) ) +
      ( sizeof(ovs_be32) + sizeof(ovs_be32) ) ;

  const size_t tlv_size_aligned =
      tlv_size + (8 - (tlv_size % 8)) % 8;

  const size_t size =
      sizeof(nx_flow_mod) +
      sizeof(ofp_action_output) +
      tlv_size_aligned;

  nx_flow_mod* ofm;

  raw_of = boost::shared_array<uint8_t>(new uint8_t[size]);
  ofm = (nx_flow_mod*) raw_of.get();
  memset(raw_of.get(), 0, size);

  ofm->nxh.header.version = v1::OFP_VERSION;
  ofm->nxh.header.type = OFPT_VENDOR;
  ofm->nxh.header.length = htons(size);

  ofm->nxh.vendor = htonl(NX_VENDOR_ID);
  ofm->nxh.subtype = htonl(NXT_FLOW_MOD);

  ofm->cookie = 0;
  ofm->command = htons(OFPFC_ADD);
  ofm->buffer_id = htonl(-1);
  ofm->idle_timeout = htons(5);
  ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
  ofm->priority = htons(OFP_DEFAULT_PRIORITY);
  ofm->flags = htons(0);
  ofm->match_len = htons(tlv_size);

  ovs_be32 nx_eth = htonl(NXM_OF_ETH_TYPE);
  ovs_be16 eth_type = htons(0x8847);

  memcpy(raw_of.get() + sizeof(nx_flow_mod),
      &nx_eth, sizeof(ovs_be32));
  memcpy(raw_of.get() + sizeof(nx_flow_mod) + sizeof(ovs_be32),
      &eth_type, sizeof(uint16_t));


  ovs_be32 label_type = htonl(NXM_NX_MPLS_LABEL);
  ovs_be32 label = htonl(0x000FFFFF & l);

  memcpy(raw_of.get() + sizeof(nx_flow_mod)
      + sizeof(ovs_be32) + sizeof(uint16_t),
      &label_type, sizeof(uint32_t));
  memcpy(raw_of.get() + sizeof(nx_flow_mod)
      + sizeof(ovs_be32) + sizeof(uint16_t) + sizeof(ovs_be32),
      &label, sizeof(uint32_t));

  nx_action_pop_mpls& action2 = *(
   (nx_action_pop_mpls*) (raw_of.get() +
       sizeof(nx_flow_mod) + tlv_size_aligned )
   );


  ofp_action_output& action_output = *((ofp_action_output*) (raw_of.get()
      + sizeof(nx_flow_mod) + tlv_size_aligned));

  const auto out_it = out_set.begin();

  memset(&action_output, 0, sizeof(ofp_action_output));
  action_output.type = htons(OFPAT10_OUTPUT);
  action_output.len = htons(sizeof(ofp_action_output));
  action_output.port = htons(*out_it);
  action_output.max_len = htons(0);

  return size;
}



const size_t forward_normal(
    const v1::ofp_packet_in& pi,
    boost::shared_array<uint8_t>& raw_of,
    std::set<uint16_t> in_set,
    std::set<uint16_t> out_set
    ) {

  const size_t tlv_size =
      ( sizeof(uint32_t) + sizeof(uint16_t) ) +
      ( sizeof(uint32_t) + sizeof(uint64_t)*2 );

  const size_t tlv_size_aligned =
      tlv_size + (8 - (tlv_size % 8)) % 8;

  const size_t size =
      sizeof(nx_flow_mod) +
      sizeof(ofp_action_output) +
      sizeof(nx_action_note) +
      tlv_size_aligned;

  raw_of = boost::shared_array<uint8_t>(new uint8_t[size]);

  const ip6_hdr& ip6 = pull_type<const ip6_hdr>(pi.packet(), sizeof(eth_header) );

  nx_flow_mod* ofm = (nx_flow_mod*) raw_of.get();
  memset(raw_of.get(), 0, size);

  ofm->nxh.header.version = openflow::v1::OFP_VERSION;
  ofm->nxh.header.type = OFPT_VENDOR;
  ofm->nxh.header.length = htons(size);

  ofm->nxh.vendor = htonl(NX_VENDOR_ID);
  ofm->nxh.subtype = htonl(NXT_FLOW_MOD);

  ofm->cookie = htonll(0);
  ofm->command = htons(OFPFC_ADD);
  ofm->buffer_id = htonl(-1);
  ofm->idle_timeout = htons(5);
  ofm->hard_timeout = htons(0);
  ofm->priority = htons(0x8000);
  ofm->flags = htons(0); // XXX
  ofm->match_len = htons(tlv_size);

  uint32_t nx_eth = htonl(NXM_OF_ETH_TYPE);
  uint16_t eth_type = htons(0x86dd);

  memcpy(raw_of.get() + sizeof(nx_flow_mod),
      &nx_eth, sizeof(uint32_t));
  memcpy(raw_of.get() + sizeof(nx_flow_mod) + sizeof(uint32_t),
      &eth_type, sizeof(uint16_t));

  uint32_t nx_header = htonl(NXM_NX_IPV6_DST);

  memcpy(raw_of.get() + sizeof(nx_flow_mod) +
      sizeof(uint32_t) + sizeof(uint16_t),
      &nx_header, sizeof(uint32_t));
  memcpy(raw_of.get() + sizeof(nx_flow_mod) +
      sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint32_t),
      &ip6.ip6_dst, sizeof(uint64_t)*2);

   nx_action_note& action_note = *(
   (nx_action_note*) (raw_of.get() +
       sizeof(nx_flow_mod) + sizeof(ofp_action_output) + tlv_size_aligned )
   );

   memset(&action_note, 0, sizeof(nx_action_note));
   action_note.type = htons(0xffff);;
   action_note.len = htons(16);
   action_note.vendor = htonl(NX_VENDOR_ID);
   action_note.subtype =  htons(NXAST_NOTE);

  ofp_action_output& action_output = *((ofp_action_output*) (raw_of.get()
      + sizeof(nx_flow_mod) + tlv_size_aligned));

  auto out_it = out_set.begin();

  memset(&action_output, 0, sizeof(ofp_action_output));
  action_output.type = htons(OFPAT10_OUTPUT);
  action_output.len = htons(sizeof(ofp_action_output));
  action_output.port = htons(*out_it);
  action_output.max_len = htons(0);

  return size;
}




}


#endif /* COMMANDS_HH_ */

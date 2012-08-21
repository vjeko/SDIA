/* Copyright 2008 (C) Nicira, Inc.
 *
 * This file is part of NOX.
 *
 * NOX is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NOX is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NOX.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <boost/bind.hpp>

#include <tbb/concurrent_hash_map.h>

#include <cstring>
#include <netinet/in.h>
#include <stdexcept>
#include <stdint.h>

#include "assert.hh"
#include "component.hh"
#include "vlog.hh"

#include "netinet++/datapathid.hh"
#include "netinet++/ethernetaddr.hh"
#include "netinet++/ethernet.hh"

#include "openflow/openflow-event.hh"
#include "openflow/openflow-datapath-join-event.hh"
#include "openflow/openflow-datapath-leave-event.hh"

#include <netinet/ip6.h>
#include "openflow/nicira-ext.h"

using namespace vigil;
using namespace openflow;

namespace
{

Vlog_module lg("switch");

class Switch
    : public Component
{
public:
    Switch(const Component_context* c)
        : Component(c)
    {
    }

    void configure();

    void install() {}

    Disposition handle_datapath_join(const Event&);
    Disposition handle_datapath_leave(const Event&);
    Disposition handle_packet_in(const Event&);

    template<class Type>
    const Type& pull_type(
        const boost::asio::const_buffer& buffer,
        size_t size) {
      const char* p = boost::asio::buffer_cast<const char*>(buffer);
      const Type* t = (const Type*) (p + size);
      return *t;
    }

private:
    struct datapath_hasher {
        static size_t hash(const datapathid& o) {
            return boost::hash_value(o.as_host());
        }
        static bool equal(const datapathid& o1, const datapathid& o2)
        {
            return o1 == o2;
        }
    };
    typedef std::map<ethernetaddr, int> mac_table;
    typedef tbb::concurrent_hash_map<datapathid, mac_table, datapath_hasher> mac_table_map;

    mac_table_map mac_tables;

    /* Set up a flow when we know the destination of a packet?  This should
     * ordinarily be true; it is only usefully false for debugging purposes. */
    bool setup_flows;
};

inline void
Switch::configure()
{
    register_handler("Openflow_datapath_join_event", (boost::bind(&Switch::handle_datapath_join, this, _1)));
    register_handler("Openflow_datapath_leave_event", (boost::bind(&Switch::handle_datapath_leave, this, _1)));
    register_handler("ofp_packet_in", (boost::bind(&Switch::handle_packet_in, this, _1)));
}

inline Disposition
Switch::handle_datapath_join(const Event& e)
{
    auto& dpje = assert_cast<const Openflow_datapath_join_event&>(e);
    mac_tables.insert(std::make_pair(dpje.dp->id(), mac_table()));
    return CONTINUE;
}

inline Disposition
Switch::handle_datapath_leave(const Event& e)
{
    auto& dple = assert_cast<const Openflow_datapath_leave_event&>(e);
    mac_tables.erase(dple.dp->id());
    return CONTINUE;
}

inline Disposition
Switch::handle_packet_in(const Event& e)
{
  auto ofe = assert_cast<const Openflow_event&>(e);
  auto& dp = ofe.dp;
  auto pi = *(assert_cast<const v1::ofp_packet_in*>(ofe.msg));
  int out_port = -1;        // Flood by default

  v1::ofp_match flow;
  flow.from_packet(pi.in_port(), pi.packet());

  //printf("Sending LLDP %016lx:%d\n", lldp_hdr->dp, lldp_hdr->port_number);

  std::cout << "PACKET" << std::endl;

  int port_num;

  if (pi.in_port() == 1){
    port_num = 2;
  } else {
    port_num = 1;
  }
  auto po = v1::ofp_packet_out()
    .in_port(pi.in_port())
    .packet(pi.packet())
    .buffer_id(-1);
  auto ao = v1::ofp_action_output().port(port_num);
  po.add_action(&ao);
  dp.send(&po);
}

REGISTER_COMPONENT(Simple_component_factory<Switch>, Switch);

} // unnamed namespace

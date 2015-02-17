/*
 * This file is part of the NetFPGA 10G UPB OpenFlow Switch project
 *
 * Copyright (c) 2014, 2015 Jörg Niklas, osjsn@niklasfamily.de
 *
 * Project Group "On-the-Fly Networking for Big Data"
 * SFB 901 "On-The-Fly Computing"
 *
 * University of Paderborn
 * Computer Engineering Group
 * Pohlweg 47 - 49
 * 33098 Paderborn
 * Germany
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "upb_netfpga.h"

#include "stdio.h"
#include "hmap.h"
#include "ofp-actions.h"
#include "assert.h"

#include <sdn_dp_cwrapper.h>

void upb_ovs_support_modify_flow_(
		struct ofproto *ofproto,
		struct rule *rule,
		enum upb_action_t *action,
		uint16_t *egress_ports
);

const char *upb_ovs_support_get_port_name(const struct ofproto *ofproto, ofp_port_t ofp_port)
{
	struct ofport *port;
	HMAP_FOR_EACH_IN_BUCKET (port, hmap_node, hash_ofp_port(ofp_port), &ofproto->ports) {

		if (port->ofp_port == ofp_port) {

			// found the port
			return netdev_get_name(port->netdev);
		}
	}
	return NULL;
}

/*
 * Each bit in upb_comp_flow indicates, that this bit of the OVS flow is supported on the NetFPGA
 */
struct flow upb_comp_flow;

void upb_ovs_support_construct(void)
{
	memset(&upb_comp_flow, 0, sizeof(struct flow));

	upb_comp_flow.in_port.ofp_port = 0xffff; // Input port (only ofp_port supported)
	memset(upb_comp_flow.dl_dst, 0xff, 6); // Ethernet destination address
	memset(upb_comp_flow.dl_src, 0xff, 6); // Ethernet source address
	upb_comp_flow.dl_type = 0xffff; // Ethernet frame type

	upb_comp_flow.vlan_tci = 0xffff; // VLAN TCI
	upb_comp_flow.nw_src = 0xffffffff; // IPv4 source address
	upb_comp_flow.nw_dst = 0xffffffff; // IPv4 destination address

	upb_comp_flow.nw_tos = 0xfc; // IP TOS: only the 6 upper bits are relevant
	upb_comp_flow.nw_proto = 0xff; // IP protocol or low 8 bits of ARP opcode

	upb_comp_flow.tp_src = 0xffff;
	upb_comp_flow.tp_dst = 0xffff;
}

int upb_ovs_support_add_port(struct ofproto *ofproto, struct netdev *netdev)
{
	if (strcmp(netdev_get_type(netdev), "system") == 0) {
		// it is a "real" network port (in opposite to a "internal" port, like a bridge)

		uint32_t temp_dataplane_id;
		if (upb_get_data_plane_id(netdev_get_name(netdev), &temp_dataplane_id) == UPB_ERROR_OK) {
			// it is a NetFPGA port

			if (ofproto->upb_dataplane_id == (uint32_t)-1) {
				// no data plane associated yet

				if (upb_create_data_plane(temp_dataplane_id, ofproto->name) == UPB_ERROR_OK) {
					ofproto->upb_dataplane_id = temp_dataplane_id;
				}

			} else {
				// there is already a NetFPGA dataplane associated with this bridge

				if (ofproto->upb_dataplane_id != temp_dataplane_id) {
					upb_log_error("The bridge has ports that belong to more than one NetFPGA. This cannot be accelerated in hardware.");
				}
			}
		}
	}

	return 0;
}

void upb_ovs_support_add_flow(struct ofproto *ofproto, uint8_t table_id, struct ofputil_flow_mod *fm, struct rule *rule)
{
	assert(rule->upb_flow_ref == (uint64_t)-1); // the "flow pointer" already has to be initialized as "invalid"

    // decide if we can accelerate or ignore this "add flow"
	if (
			!(fm->flags & OFPUTIL_FF_HIDDEN_FIELDS) // not an internal flow with hidden fielde
		&&	fm->priority <= UINT16_MAX // no "virtual" priority
		&&	table_id == 0 // only table 0 can be accelerated
		&&	ofproto->upb_dataplane_id != (uint32_t)-1 // this bridge has NetFPGA acceleration enabled

	) {
		bool flow_supported = true; // whenever we cannot transform some part of the flow we set this to false

		enum upb_action_t action;
		uint16_t egress_ports;

		struct upb_flow_t flow_key, flow_mask;
		upb_clear_flow(&flow_key);
		upb_clear_flow(&flow_mask);


		// transform as much as possible to the upb's flow representation
		// if some part of the flow cannot be transformed we transform as much as possible anyway (for visualization purposes)

		if (fm->match.wc.masks.in_port.ofp_port == 0xffff) { // full match for ingress port

			const char *port_name = upb_ovs_support_get_port_name(rule->ofproto, fm->match.flow.in_port.ofp_port);
			if (port_name) {

				uint32_t temp_dataplane_id;
				if (
						upb_get_ingress_port(port_name, &flow_key.ingress_port, &temp_dataplane_id) != UPB_ERROR_OK // the port is not on the netfpga...
					||	temp_dataplane_id != ofproto->upb_dataplane_id //...or does not belongs to the ovs bridge's netfpga data plane
				) {
					// we are wrong here
					return;
				}
			} else {

				upb_log_error("Error: We could not get a name for the OpenVSwitch port");
				flow_supported = false;
			}

			flow_mask.ingress_port = 0xffff;

		} else if (fm->match.wc.masks.in_port.ofp_port == 0x0000) {
			// wildcard for ingress port

			/*
			 * Check if all ports in this ovs bridge belong to one NetFPGA card - otherwise we cannot accelerate this flow in hardware
			 * Remark: In OVS ports can also be added later.
			 */
			struct ofproto_port_dump dump;
			struct ofproto_port ofproto_port;
			OFPROTO_PORT_FOR_EACH (&ofproto_port, &dump, ofproto) {

				if (strcmp(ofproto_port.type, "system") == 0) {
					// it is a "real" network port (in opposite to a "internal" port, like a bridge)

					uint32_t temp_dataplane_id;
					if (
							upb_get_data_plane_id(ofproto_port.name, &temp_dataplane_id) != UPB_ERROR_OK
						||	ofproto->upb_dataplane_id != temp_dataplane_id
					) {
						flow_supported = false;
					}
				}
			}

			flow_key.ingress_port = 0;
			flow_mask.ingress_port = 0;

		} else { // only some bits are wildcarded -> unsupported

			flow_supported = false;
		}

		// copy source & destination MAC address
		memcpy(&flow_key.src_mac, &fm->match.flow.dl_src, 6);
		memcpy(&flow_mask.src_mac, &fm->match.wc.masks.dl_src, 6);
		memcpy(&flow_key.dst_mac, &fm->match.flow.dl_dst, 6);
		memcpy(&flow_mask.dst_mac, &fm->match.wc.masks.dl_dst, 6);

		// copy Ethernet frame type
		flow_key.ethertype = fm->match.flow.dl_type;
		flow_mask.ethertype = fm->match.wc.masks.dl_type;

		// set vlan id
		flow_key.vlan_id = ((fm->match.flow.vlan_tci >> 12) & 0xf) | ((fm->match.flow.vlan_tci << 4) & 0xf0) | (fm->match.flow.vlan_tci & 0xf00);
		flow_mask.vlan_id = ((fm->match.wc.masks.vlan_tci >> 12) & 0xf) | ((fm->match.wc.masks.vlan_tci << 4) & 0xf0) | (fm->match.wc.masks.vlan_tci & 0xf00);

		// set vlan pcp
		flow_key.vlan_pcp = (fm->match.flow.vlan_tci >> 5) & 0x7;
		flow_mask.vlan_pcp = (fm->match.wc.masks.vlan_tci >> 5) & 0x7;

		// copy IPv4 source and destination addresses
		flow_key.src_ip = fm->match.flow.nw_src;
		flow_mask.src_ip = fm->match.wc.masks.nw_src;
		flow_key.dst_ip = fm->match.flow.nw_dst;
		flow_mask.dst_ip = fm->match.wc.masks.nw_dst;

		// copy TOS
		flow_key.ip_tos = fm->match.flow.nw_tos;
		flow_mask.ip_tos = fm->match.wc.masks.nw_tos;

		// copy IP protocol
		flow_key.ip_prot = fm->match.flow.nw_proto;
		flow_mask.ip_prot = fm->match.wc.masks.nw_proto;

		// copy transport source and destination port
		flow_key.src_port = fm->match.flow.tp_src;
		flow_mask.src_port = fm->match.wc.masks.tp_src;
		flow_key.dst_port = fm->match.flow.tp_dst;
		flow_mask.dst_port = fm->match.wc.masks.tp_dst;

		/*
		 * Special cautions with the IP protocol and the UPB NetFPGA project:
		 *
		 * 132 (SCTP): only wildcard on tp_src and tp_dst is allowed (UPB NetFPGA can not parse SCTP)
		 * (this check does not catch all crazy cases but it should be enough)
		 */

		if (
				fm->match.flow.nw_proto == 132
			&&	fm->match.wc.masks.nw_proto == 0xff
			&&	(	fm->match.wc.masks.tp_src != 0
				||	fm->match.wc.masks.tp_dst != 0)

		) { // SCTP matches but transport source and destination is not wildcarded
			flow_supported = false;
		}

		// check if the whole OVS mask fits to NetFPGA
		{
			uint32_t flow_size_words = sizeof(struct flow) / 4;
			uint32_t i;

			assert(sizeof(struct flow) % 4 == 0);

			for (i = 0; i < flow_size_words; i++) {

				if (
						(((uint32_t*)&fm->match.wc.masks)[i] & ((uint32_t*)&upb_comp_flow)[i])
					!=	((uint32_t*)&fm->match.wc.masks)[i]
				) {
					/*
					 * If a bit is set in ovs's mask which is not set in upb_comp_flow,
					 * then we cannot accelerate the flow on the NetFPGA
					 */
					flow_supported = false;
					break;
				}
			}
		}

		upb_ovs_support_modify_flow_(ofproto, rule, &action, &egress_ports);

		// ...and finally add the flow
		upb_add_flow(ofproto->upb_dataplane_id, &rule->upb_flow_ref, !flow_supported, &flow_key, &flow_mask, fm->priority, action, egress_ports);
	}
}

void upb_ovs_support_modify_flow(
		struct ofproto *ofproto,
		struct rule *rule,
		bool reset_counters
) {
	enum upb_action_t action;
	uint16_t egress_ports;

	upb_ovs_support_modify_flow_(ofproto, rule, &action, &egress_ports);

	upb_modify_flow(rule->upb_flow_ref, action, egress_ports, reset_counters);
}

void upb_ovs_support_modify_flow_(
		struct ofproto *ofproto,
		struct rule *rule,
		enum upb_action_t *action,
		uint16_t *egress_ports
) {
	const struct ofpact *a;

	*action = UPB_ACTION_UNSET;
	*egress_ports = 0;

	OFPACT_FOR_EACH (a, rule->actions.p->ofpacts, rule->actions.p->ofpacts_len) {

		if (a->type == OFPACT_OUTPUT) {

			struct ofpact_output *action_output = ofpact_get_OUTPUT(a);
			ofp_port_t port = action_output->port;
			switch (port) {

				case OFPP_TABLE: // Perform actions in flow table
				case OFPP_NORMAL: // Process with normal L2 switch - unsupported (this can be easily implemented on the fpga - a l2 switch is available and the action transmission is also implemented)
				case OFPP_FLOOD: // All ports except input port and those disabled by STP
				case OFPP_CONTROLLER: // Send to controller
				case OFPP_LOCAL: // Local openflow "port"
				case OFPP_NONE: // Not associated with any port
					/*
					 * Unsupported actions: Packets will be forwarded to OpenVSwitch
					 */
					*action = UPB_ACTION_SEND_TO_CONTROLLER;
					break;

				case OFPP_IN_PORT: // Forward to input port
					if (*action == UPB_ACTION_UNSET || *action == UPB_ACTION_BACK_TO_IN_PORT) {
						*action = UPB_ACTION_BACK_TO_IN_PORT;
					} else {
						*action = UPB_ACTION_SEND_TO_CONTROLLER;
					}
					break;

				case OFPP_ALL: // All ports except input port
					if (*action == UPB_ACTION_UNSET || *action == UPB_ACTION_BROADCAST) {
						*action = UPB_ACTION_BROADCAST;
					} else {
						*action = UPB_ACTION_SEND_TO_CONTROLLER;
					}
					break;

				default: {

					const char *port_name = NULL;
					uint32_t ports_dataplane_id;
					if (
							port < OFPP_MAX // port is in valid range
						&&	(port_name = upb_ovs_support_get_port_name(rule->ofproto, port)) // ovs has a valid port name for it
						&&	(*action == UPB_ACTION_UNSET || *action == UPB_ACTION_FORWARD) // only compatible actions before
						&&	upb_add_egress_port_bits(port_name, egress_ports, &ports_dataplane_id) == UPB_ERROR_OK // we find a NetFPGA port for it
						&&	ports_dataplane_id == ofproto->upb_dataplane_id // the destination port is within the same data plane
					) {
						*action = UPB_ACTION_FORWARD;
					} else {
						*action = UPB_ACTION_SEND_TO_CONTROLLER;
					}
				} break;
			}

		} else { // unsupported action (something else than 'OUTPUT' (= 'forward'))
			*action = UPB_ACTION_SEND_TO_CONTROLLER;
		}
	}

	if (*action == UPB_ACTION_UNSET) {
		/*
		 * This is a drop rule (took me quite some time to understand that...)
		 */
		*action = UPB_ACTION_FORWARD; // we can also forward to nowhere
	}
}

void upb_ovs_support_delete_flow(struct rule *rule)
{
	if (rule->upb_flow_ref != (uint64_t)-1) {
		upb_delete_flow(rule->upb_flow_ref);
	}
}

void upb_ovs_support_get_flow_statistics(struct rule *rule, uint64_t *packets, uint64_t *bytes, uint64_t *ms_since_last_packet)
{
	if (rule->upb_flow_ref != (uint64_t)-1) {
		upb_get_statistics(rule->upb_flow_ref, packets, bytes, ms_since_last_packet);
	} else {
		*packets = 0;
		*bytes = 0;
		*ms_since_last_packet = (uint64_t)-1;
	}
}


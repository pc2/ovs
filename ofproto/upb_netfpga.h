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

#pragma once

#include "ofp-util.h"
#include "ofproto-provider.h"

int upb_ovs_support_add_port(struct ofproto *ofproto, struct netdev *netdev);
void upb_ovs_support_construct(void);
const char *upb_ovs_support_get_port_name(const struct ofproto *ofproto, ofp_port_t ofp_port);
void upb_ovs_support_copy_mac_change_byte_order(uint8_t *in, uint8_t *out);
void upb_ovs_support_add_flow(struct ofproto *ofproto, uint8_t table_id, struct ofputil_flow_mod *fm, struct rule *rule);
void upb_ovs_support_modify_flow(struct ofproto *ofproto, struct rule *rule, bool reset_counters);
void upb_ovs_support_delete_flow(struct rule *rule);
void upb_ovs_support_get_flow_statistics(struct rule *rule, uint64_t *packets, uint64_t *bytes, uint64_t *ms_since_last_packet);

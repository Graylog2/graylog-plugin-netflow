/**
 * Copyright (C) 2012, 2013, 2014 wasted.io Ltd <really@wasted.io>
 * Copyright (C) 2015-2017 Graylog, Inc. (hello@graylog.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.graylog.plugins.netflow.codecs;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.graylog.plugins.netflow.flows.TemplateRecord;

import javax.annotation.Nullable;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class TemplateStore {
    // Future work file IO to add more field types, ==> do IPFix
    // Support for v9 was tested on a Cisco ASA 5500 and a Cisco Meraki MX84

    // FIXME: This will grow indefinitely
    private final ConcurrentMap<Integer, TemplateRecord> idToRecord = new ConcurrentHashMap<>();

    // https://tools.ietf.org/html/rfc3954#section-8
    // http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
    // http://www.cisco.com/c/en/us/td/docs/security/asa/special/netflow/guide/asa_netflow.html
    static private Map<Integer, String> idToString = ImmutableMap.<Integer, String>builder()
            .put(1, "in_bytes")
            .put(2, "in_packets")
            .put(3, "flows")
            .put(4, "protocol")
            .put(5, "src_type_of_service")
            .put(6, "tcp_flags")
            .put(7, "src_port")
            .put(8, "src_addr")
            .put(9, "src_mask")
            .put(10, "input_snmp")
            .put(11, "dst_port")
            .put(12, "dst_addr")
            .put(13, "dst_mask")
            .put(14, "output_snmp")
            .put(15, "ipv4_next_hop")
            .put(16, "src_as")
            .put(17, "dst_As")
            .put(18, "bgp_ipv4_next_hop")
            .put(19, "mul_dst_packets")
            .put(20, "mul_dst_bytes")
            .put(21, "last_switched")
            .put(22, "first_switched")
            .put(23, "out_bytes")
            .put(24, "out_packets")
            .put(25, "min_packet_length")
            .put(26, "max_packet_length")
            .put(27, "ipv6_src_addr")
            .put(28, "ipv6_dst_addr")
            .put(29, "ipv6_src_mask")
            .put(30, "ipv6_dst_mask")
            .put(31, "ipv6_flow_label")
            .put(32, "icmp_type")
            .put(33, "mul_igmp_type")
            .put(34, "sampling_interval")
            .put(35, "sampling_algorithm")
            .put(36, "flow_active_timeout")
            .put(37, "flow_inactive_timeout")
            .put(38, "engine_type")
            .put(39, "engine_id")
            .put(40, "total_bytes_exp")
            .put(41, "total_packets_exp")
            .put(42, "total_flows_exp")
            .put(43, "vendor_proprietary_43")
            .put(44, "ipv4_src_previx")
            .put(45, "ipv4_dst_prefix")
            .put(46, "mpls_top_label_type")
            .put(47, "mpls_top_label_ip_addr")
            .put(48, "flow_sampler_id")
            .put(49, "flow_sampler_mode")
            .put(50, "flow_sampler_random_interval")
            .put(51, "vendor_proprietary_51")
            .put(52, "min_ttl")
            .put(53, "max_ttl")
            .put(54, "ipv4_ident")
            .put(55, "dst_tos")
            .put(56, "in_src_mac")
            .put(57, "out_dst_mac")
            .put(58, "src_vlan")
            .put(59, "dst_vlan")
            .put(60, "ip_protocol_version")
            .put(61, "direction")
            .put(62, "ipv6_next_hop")
            .put(63, "bpg_ipv6_next_hop")
            .put(64, "ipv6_option_headers")
            .put(65, "vendor_proprietary_65")
            .put(66, "vendor_proprietary_66")
            .put(67, "vendor_proprietary_67")
            .put(68, "vendor_proprietary_68")
            .put(69, "vendor_proprietary_69")
            .put(70, "mpls_label_1")
            .put(71, "mpls_label_2")
            .put(72, "mpls_label_3")
            .put(73, "mpls_label_4")
            .put(74, "mpls_label_5")
            .put(75, "mpls_label_6")
            .put(76, "mpls_label_7")
            .put(77, "mpls_label_8")
            .put(78, "mpls_label_9")
            .put(79, "mpls_label_10")
            .put(80, "in_dst_mac")
            .put(81, "out_src_mac")
            .put(82, "interface_name")
            .put(83, "interface_description")
            .put(84, "sampler_name")
            .put(85, "in_permanent_bytes")
            .put(86, "in_permanent_packets")
            .put(87, "vendor_proprietary_87")
            .put(88, "fragment_offset")
            .put(89, "forwarding_status")
            .put(90, "mpls_pal_rd")
            .put(91, "mpls_prefix_length")
            .put(92, "src_traffic_index")
            .put(93, "dst_traffic_index")
            .put(94, "application_description")
            .put(95, "application_tag")
            .put(96, "application_name")
            .put(98, "dscp_codepoint")
            .put(99, "replication_factor")
            .put(100, "deprecated_100")
            .put(102, "l2_packet_section_offset")
            .put(103, "l2_packet_section_size")
            .put(104, "l2_packet_section_data")
            .put(148, "nf_f_conn_id")
            .put(152, "nf_f_flow_create_time_msec")
            .put(176, "nf_f_icmp_type")
            .put(177, "nf_f_icmp_code")
            .put(178, "nf_f_icmp_type_ipv6")
            .put(179, "nf_f_icmp_code_ipv6")
            .put(225, "nf_f_xflate_src_addr_ipv4")
            .put(226, "nf_f_xflate_dst_addr_ipv4")
            .put(227, "nf_f_xflate_src_port")
            .put(228, "nf_f_xflate_dst_port")
            .put(231, "nf_f_fwd_flow_delta_bytes")
            .put(232, "nf_f_rev_flow_delta_bytes")
            .put(233, "nf_f_fw_event")
            .put(281, "nf_f_xflate_src_addr_ipv6")
            .put(282, "nf_f_xflate_dst_addr_ipv6")
            .put(323, "nf_f_event_time_msec")
            .put(33000, "nf_f_ingress_acl_id")
            .put(33001, "nf_f_egress_acl_id")
            .put(33002, "nf_f_fw_ext_event")
            .put(40000, "nf_f_username")
            // .put(40000, "nf_f_username_max")
            .build();

    static private Set<Integer> inetIds = ImmutableSet.<Integer>builder()
            // IPv4 fields
            .add(18)
            .add(15)
            .add(12)
            .add(8)
            .add(44)
            .add(45)
            // IPv6 Fields
            .add(27)
            .add(28)
            .add(62)
            .add(63)
            .add(281)
            .add(282)
            .build();

    public void putIdToRecord(TemplateRecord templateRecord) {
        idToRecord.put(templateRecord.getId(), templateRecord);
    }

    @Nullable
    public TemplateRecord getTemplate(int flowSetId) {
        return idToRecord.get(flowSetId);
    }

    public boolean isIP(int id) {
        return inetIds.contains(id);
    }

    @Nullable
    public String getString(int fieldType) {
        return idToString.get(fieldType);
    }

    public String getStringOrElse(int fieldType, String defaultValue) {
        return idToString.getOrDefault(fieldType, defaultValue);
    }
}

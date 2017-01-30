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

import java.util.HashMap;
import java.util.HashSet;

import org.graylog.plugins.netflow.flows.TemplateRecord;

import javax.annotation.Nullable;

public class TemplateStore {
	// Future work file IO to add more field types, ==> do IPFix
	// Support for v9 was tested on a Cisco ASA 5500 and a Cisco Meraki MX84
	
	private HashMap<Integer,TemplateRecord> idToRecord = new HashMap<>();
	
	static private HashMap<Integer,String> idToString = new HashMap<>();
	{
		idToString.put(1,"in_bytes");
		idToString.put(2,"in_packets");
		idToString.put(3,"flows");
		idToString.put(4,"protocol");
		idToString.put(5,"src_type_of_service");
		idToString.put(6,"tcp_flags");
		idToString.put(7,"src_port");
		idToString.put(8,"src_addr");
		idToString.put(9,"src_mask");
		idToString.put(10,"input_snmp");
		idToString.put(11,"dst_port");
		idToString.put(12,"dst_addr");
		idToString.put(13,"dst_mask");
		idToString.put(14,"output_snmp");
		idToString.put(15,"ipv4_next_hop");
		idToString.put(16,"src_as");
		idToString.put(17,"dst_As");
		idToString.put(18,"bgp_ipv4_next_hop");
		idToString.put(19,"mul_dst_packets");
		idToString.put(20,"mul_dst_bytes");
		idToString.put(21,"last_switched");
		idToString.put(22,"first_switched");
		idToString.put(23,"out_bytes");
		idToString.put(24,"out_packets");
		idToString.put(25,"min_packet_length");
		idToString.put(26,"max_packet_length");
		idToString.put(27,"ipv6_src_addr");
		idToString.put(28,"ipv6_dst_addr");
		idToString.put(29,"ipv6_src_mask");
		idToString.put(30,"ipv6_dst_mask");
		idToString.put(31,"ipv6_flow_label");
		idToString.put(32,"icmp_type");
		idToString.put(33,"mul_igmp_type");
		idToString.put(34,"sampling_interval");
		idToString.put(35,"sampling_algorithm");
		idToString.put(36,"flow_active_timeout");
		idToString.put(37,"flow_inactive_timeout");
		idToString.put(38,"engine_type");
		idToString.put(39,"engine_id");
		idToString.put(40,"total_bytes_exp");
		idToString.put(41,"total_packets_exp");
		idToString.put(42,"total_flows_exp");
		idToString.put(43,"vendor_proprietary_43");
		idToString.put(44,"ipv4_src_previx");
		idToString.put(45,"ipv4_dst_prefix");
		idToString.put(46,"mpls_top_label_type");
		idToString.put(47,"mpls_top_label_ip_addr");
		idToString.put(48,"flow_sampler_id");
		idToString.put(49,"flow_sampler_mode");
		idToString.put(50,"flow_sampler_random_interval");
		idToString.put(51,"vendor_proprietary_51");
		idToString.put(52,"min_ttl");
		idToString.put(53,"max_ttl");
		idToString.put(54,"ipv4_ident");
		idToString.put(55,"dst_tos");
		idToString.put(56,"in_src_mac");
		idToString.put(57,"out_dst_mac");
		idToString.put(58,"src_vlan");
		idToString.put(59,"dst_vlan");
		idToString.put(60,"ip_protocol_version");
		idToString.put(61,"direction");
		idToString.put(62,"ipv6_next_hop");
		idToString.put(63,"bpg_ipv6_next_hop");
		idToString.put(64,"ipv6_option_headers");
		idToString.put(65,"vendor_proprietary_65");
		idToString.put(66,"vendor_proprietary_66");
		idToString.put(67,"vendor_proprietary_67");
		idToString.put(68,"vendor_proprietary_68");
		idToString.put(69,"vendor_proprietary_69");
		idToString.put(70,"mpls_label_1");
		idToString.put(71,"mpls_label_2");
		idToString.put(72,"mpls_label_3");
		idToString.put(73,"mpls_label_4");
		idToString.put(74,"mpls_label_5");
		idToString.put(75,"mpls_label_6");
		idToString.put(76,"mpls_label_7");
		idToString.put(77,"mpls_label_8");
		idToString.put(78,"mpls_label_9");
		idToString.put(79,"mpls_label_10");
		idToString.put(80,"in_dst_mac");
		idToString.put(81,"out_src_mac");
		idToString.put(82,"interface_name");
		idToString.put(83,"interface_description");
		idToString.put(84,"sampler_name");
		idToString.put(85,"in_permanent_bytes");
		idToString.put(86,"in_permanent_packets");
		idToString.put(87,"vendor_proprietary_87");
		idToString.put(88,"fragment_offset");
		idToString.put(89,"forwarding_status");
		idToString.put(90,"mpls_pal_rd");
		idToString.put(91,"mpls_prefix_length");
		idToString.put(92,"src_traffic_index");
		idToString.put(93,"dst_traffic_index");
		idToString.put(94,"application_description");
		idToString.put(95,"application_tag");
		idToString.put(96,"application_name");
		idToString.put(98,"dscp_codepoint");
		idToString.put(99,"replication_factor");
		idToString.put(100,"deprecated_100");
		idToString.put(102,"l2_packet_section_offset");
		idToString.put(103,"l2_packet_section_size");
		idToString.put(104,"l2_packet_section_data");
		idToString.put(148,"nf_f_conn_id");
		idToString.put(152,"nf_f_flow_create_time_msec");
		idToString.put(176,"nf_f_icmp_type");
		idToString.put(177,"nf_f_icmp_code");
		idToString.put(178,"nf_f_icmp_type_ipv6");
		idToString.put(179,"nf_f_icmp_code_ipv6");
		idToString.put(225,"nf_f_xflate_src_addr_ipv4");
		idToString.put(226,"nf_f_xflate_dst_addr_ipv4");
		idToString.put(227,"nf_f_xflate_src_port");
		idToString.put(228,"nf_f_xflate_dst_port");
		idToString.put(231,"nf_f_fwd_flow_delta_bytes");
		idToString.put(232,"nf_f_rev_flow_delta_bytes");
		idToString.put(233,"nf_f_fw_event");
		idToString.put(281,"nf_f_xflate_src_addr_ipv6");
		idToString.put(282,"nf_f_xflate_dst_addr_ipv6");
		idToString.put(323,"nf_f_event_time_msec");
		idToString.put(33000,"nf_f_ingress_acl_id");
		idToString.put(33001,"nf_f_egress_acl_id");
		idToString.put(33002,"nf_f_fw_ext_event");
		idToString.put(40000,"nf_f_username");
		idToString.put(40000,"nf_f_username_max");
	};
	
	static private HashSet<Integer> inetIds = new HashSet<Integer>();{
		// IPv4 fields
		inetIds.add(18);
		inetIds.add(15);
		inetIds.add(12);
		inetIds.add(8);
		inetIds.add(44);
		inetIds.add(45);
		// IPv6 Fields
		inetIds.add(27);
		inetIds.add(28);
		inetIds.add(62);
		inetIds.add(63);
		inetIds.add(281);
		inetIds.add(282);
    }

	public void putIdToRecord(TemplateRecord templateRecord) {
		idToRecord.put(templateRecord.getId(), templateRecord);
	}

	@Nullable
	public TemplateRecord getTemplate(int flowSetId) {
		return idToRecord.get(flowSetId);
	}

	public boolean isIP(int id){
		return inetIds.contains(id);
	}

	@Nullable
	public String getString(int fieldType) {
		return idToString.get(fieldType);
	}

	public String getStringOrElse(int fieldType, String string) {
		String x = idToString.get(fieldType);
		if(x == null) {
			return string;
		} else {
			return x;
		}
	}

}

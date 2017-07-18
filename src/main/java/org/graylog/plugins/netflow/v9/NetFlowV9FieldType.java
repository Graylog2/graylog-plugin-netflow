/*
 * Copyright 2013 Eediom Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.graylog.plugins.netflow.v9;

import java.util.HashMap;
import java.util.Map;

/**
 * @since 0.1.0
 * @author xeraph
 */
public enum NetFlowV9FieldType {
	IN_BYTES(1, 2, 4), IN_PKTS(2, 2, 4), FLOWS(3, 2, 4), PROTOCOL(4, 1, 1), SRC_TOS(5, 1, 1), TCP_FLAGS(6, 1, 1), L4_SRC_PORT(7,
			1, 2), IPV4_SRC_ADDR(8, 3, 4), SRC_MASK(9, 1, 1), INPUT_SNMP(10, 2, 0), L4_DST_PORT(11, 1, 2), IPV4_DST_ADDR(12, 3, 4), DST_MASK(
			13, 1, 1), OUTPUT_SNMP(14, 2, 0), IPV4_NEXT_HOP(15, 3, 4), SRC_AS(16, 1, 2), DST_AS(17, 1, 2), BGP_IPV4_NEXT_HOP(18,
			3, 4), MUL_DST_PKTS(19, 2, 4), MUL_DST_BYTES(20, 2, 4), LAST_SWITCHED(21, 2, 4), FIRST_SWITCHED(22, 2, 4), OUT_BYTES(
			23, 2, 4), OUT_PKTS(24, 2, 4), MIN_PKT_LNGTH(25, 1, 2), MAX_PKT_LNGTH(26, 1, 2), IPV6_SRC_ADDR(27, 4, 16), IPV6_DST_ADDR(
			28, 4, 16), IPV6_SRC_MASK(29, 1, 1), IPV6_DST_MASK(30, 1, 1), IPV6_FLOW_LABEL(31, 1, 3), ICMP_TYPE(32, 1, 2), MUL_IGMP_TYPE(
			33, 1, 1), SAMPLING_INTERVAL(34, 2, 4), SAMPLING_ALGORITHM(35, 1, 1), FLOW_ACTIVE_TIMEOUT(36, 1, 2), FLOW_INACTIVE_TIMEOUT(
			37, 1, 2), ENGINE_TYPE(38, 1, 1), ENGINE_ID(39, 1, 1), TOTAL_BYTES_EXP(40, 2, 4), TOTAL_PKTS_EXP(41, 2, 4), TOTAL_FLOWS_EXP(
			42, 2, 4), IPV4_SRC_PREFIX(44, 3, 4), IPV4_DST_PREFIX(45, 3, 4), MPLS_TOP_LABEL_TYPE(46, 1, 1), MPLS_TOP_LABEL_IP_ADDR(
			47, 2, 4), FLOW_SAMPLER_ID(48, 1, 1), FLOW_SAMPLER_MODE(49, 1, 1), FLOW_SAMPLER_RANDOM_INTERVAL(50, 2, 4), MIN_TTL(
			52, 1, 1), MAX_TTL(53, 1, 1), IPV4_IDENT(54, 1, 2), DST_TOS(55, 1, 1), IN_SRC_MAC(56, 5, 6), OUT_DST_MAC(57, 5, 6), SRC_VLAN(
			58, 1, 2), DST_VLAN(59, 1, 2), IP_PROTOCOL_VERSION(60, 1, 1), DIRECTION(61, 1, 1), IPV6_NEXT_HOP(62, 4, 16), BGP_IPV6_NEXT_HOP(
			63, 4, 16), IPV6_OPTION_HEADERS(64, 2, 4), MPLS_LABEL_1(70, 1, 3), MPLS_LABEL_2(71, 1, 3), MPLS_LABEL_3(72, 1, 3), MPLS_LABEL_4(
			73, 1, 3), MPLS_LABEL_5(74, 1, 3), MPLS_LABEL_6(75, 1, 3), MPLS_LABEL_7(76, 1, 3), MPLS_LABEL_8(77, 1, 3), MPLS_LABEL_9(
			78, 1, 3), MPLS_LABEL_10(79, 1, 3), IN_DST_MAC(80, 5, 6), OUT_SRC_MAC(81, 5, 6), IF_NAME(82, 6, 0), IF_DESC(83, 6, 0), SAMPLER_NAME(
			84, 6, 0), IN_PERMANENT_BYTES(85, 2, 4), IN_PERMANENT_PKTS(86, 2, 4), FRAGMENT_OFFSET(88, 1, 2), FORWARDING_STATUS(
			89, 1, 1), MPLS_PREFIX_LEN(91, 1, 1), SRC_TRAFFIC_INDEX(92, 2, 4), DST_TRAFFIC_INDEX(93, 2, 4), APP_DESC(94, 6, 0), APP_NAME(
			96, 6, 0);

	public int id;

	// 1 (int), 2 (long), 3 (ipv4), 4 (ipv6), 5 (mac), 6 (string)
	public int valueType;

	// configured by template
	public int length;

	public int defaultLength;

	private NetFlowV9FieldType(int id, int valueType, int defaultLenth) {
		this.id = id;
		this.valueType = valueType;
		this.defaultLength = defaultLenth;
	}

	private final static Map<Integer, NetFlowV9FieldType> types = new HashMap<Integer, NetFlowV9FieldType>();

	static {
		for (NetFlowV9FieldType t : values())
			types.put(t.id, t);
	}

	public static NetFlowV9FieldType parse(int type) {
		return types.get(type);
	}
}

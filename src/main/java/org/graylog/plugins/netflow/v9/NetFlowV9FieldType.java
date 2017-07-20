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

public enum NetFlowV9FieldType {
    IN_BYTES(1, ValueType.LONG, 4),
    IN_PKTS(2, ValueType.LONG, 4),
    FLOWS(3, ValueType.LONG, 4),
    PROTOCOL(4, ValueType.INT, 1),
    SRC_TOS(5, ValueType.INT, 1),
    TCP_FLAGS(6, ValueType.INT, 1),
    L4_SRC_PORT(7, ValueType.INT, 2),
    IPV4_SRC_ADDR(8, ValueType.IPV4, 4),
    SRC_MASK(9, ValueType.INT, 1),
    INPUT_SNMP(10, ValueType.LONG, 0),
    L4_DST_PORT(11, ValueType.INT, 2),
    IPV4_DST_ADDR(12, ValueType.IPV4, 4),
    DST_MASK(13, ValueType.INT, 1),
    OUTPUT_SNMP(14, ValueType.LONG, 0),
    IPV4_NEXT_HOP(15, ValueType.IPV4, 4),
    SRC_AS(16, ValueType.INT, 2),
    DST_AS(17, ValueType.INT, 2),
    BGP_IPV4_NEXT_HOP(18, ValueType.IPV4, 4),
    MUL_DST_PKTS(19, ValueType.LONG, 4),
    MUL_DST_BYTES(20, ValueType.LONG, 4),
    LAST_SWITCHED(21, ValueType.LONG, 4),
    FIRST_SWITCHED(22, ValueType.LONG, 4),
    OUT_BYTES(23, ValueType.LONG, 4),
    OUT_PKTS(24, ValueType.LONG, 4),
    MIN_PKT_LNGTH(25, ValueType.INT, 2),
    MAX_PKT_LNGTH(26, ValueType.INT, 2),
    IPV6_SRC_ADDR(27, ValueType.IPV6, 16),
    IPV6_DST_ADDR(28, ValueType.IPV6, 16),
    IPV6_SRC_MASK(29, ValueType.INT, 1),
    IPV6_DST_MASK(30, ValueType.INT, 1),
    IPV6_FLOW_LABEL(31, ValueType.INT, 3),
    ICMP_TYPE(32, ValueType.INT, 2),
    MUL_IGMP_TYPE(33, ValueType.INT, 1),
    SAMPLING_INTERVAL(34, ValueType.LONG, 4),
    SAMPLING_ALGORITHM(35, ValueType.INT, 1),
    FLOW_ACTIVE_TIMEOUT(36, ValueType.INT, 2),
    FLOW_INACTIVE_TIMEOUT(37, ValueType.INT, 2),
    ENGINE_TYPE(38, ValueType.INT, 1),
    ENGINE_ID(39, ValueType.INT, 1),
    TOTAL_BYTES_EXP(40, ValueType.LONG, 4),
    TOTAL_PKTS_EXP(41, ValueType.LONG, 4),
    TOTAL_FLOWS_EXP(42, ValueType.LONG, 4),
    IPV4_SRC_PREFIX(44, ValueType.IPV4, 4),
    IPV4_DST_PREFIX(45, ValueType.IPV4, 4),
    MPLS_TOP_LABEL_TYPE(46, ValueType.INT, 1),
    MPLS_TOP_LABEL_IP_ADDR(47, ValueType.LONG, 4),
    FLOW_SAMPLER_ID(48, ValueType.INT, 1),
    FLOW_SAMPLER_MODE(49, ValueType.INT, 1),
    FLOW_SAMPLER_RANDOM_INTERVAL(50, ValueType.LONG, 4),
    MIN_TTL(52, ValueType.INT, 1),
    MAX_TTL(53, ValueType.INT, 1),
    IPV4_IDENT(54, ValueType.INT, 2),
    DST_TOS(55, ValueType.INT, 1),
    IN_SRC_MAC(56, ValueType.MAC, 6),
    OUT_DST_MAC(57, ValueType.MAC, 6),
    SRC_VLAN(58, ValueType.INT, 2),
    DST_VLAN(59, ValueType.INT, 2),
    IP_PROTOCOL_VERSION(60, ValueType.INT, 1),
    DIRECTION(61, ValueType.INT, 1),
    IPV6_NEXT_HOP(62, ValueType.IPV6, 16),
    BGP_IPV6_NEXT_HOP(63, ValueType.IPV6, 16),
    IPV6_OPTION_HEADERS(64, ValueType.LONG, 4),
    MPLS_LABEL_1(70, ValueType.INT, 3),
    MPLS_LABEL_2(71, ValueType.INT, 3),
    MPLS_LABEL_3(72, ValueType.INT, 3),
    MPLS_LABEL_4(73, ValueType.INT, 3),
    MPLS_LABEL_5(74, ValueType.INT, 3),
    MPLS_LABEL_6(75, ValueType.INT, 3),
    MPLS_LABEL_7(76, ValueType.INT, 3),
    MPLS_LABEL_8(77, ValueType.INT, 3),
    MPLS_LABEL_9(78, ValueType.INT, 3),
    MPLS_LABEL_10(79, ValueType.INT, 3),
    IN_DST_MAC(80, ValueType.MAC, 6),
    OUT_SRC_MAC(81, ValueType.MAC, 6),
    IF_NAME(82, ValueType.STRING, 0),
    IF_DESC(83, ValueType.STRING, 0),
    SAMPLER_NAME(84, ValueType.STRING, 0),
    IN_PERMANENT_BYTES(85, ValueType.LONG, 4),
    IN_PERMANENT_PKTS(86, ValueType.LONG, 4),
    FRAGMENT_OFFSET(88, ValueType.INT, 2),
    FORWARDING_STATUS(89, ValueType.INT, 1),
    MPLS_PREFIX_LEN(91, ValueType.INT, 1),
    SRC_TRAFFIC_INDEX(92, ValueType.LONG, 4),
    DST_TRAFFIC_INDEX(93, ValueType.LONG, 4),
    APP_DESC(94, ValueType.STRING, 0),
    APP_NAME(96, ValueType.STRING, 0);

    public final int id;

    public final ValueType valueType;

    public final int defaultLength;

    NetFlowV9FieldType(int id, ValueType valueType, int defaultLength) {
        this.id = id;
        this.valueType = valueType;
        this.defaultLength = defaultLength;
    }

    private final static Map<Integer, NetFlowV9FieldType> types = new HashMap<Integer, NetFlowV9FieldType>();

    static {
        for (NetFlowV9FieldType t : values()) {
            types.put(t.id, t);
        }
    }

    public static NetFlowV9FieldType parse(int type) {
        return types.get(type);
    }

    enum ValueType {
        INT, LONG, IPV4, IPV6, MAC, STRING
    }
}

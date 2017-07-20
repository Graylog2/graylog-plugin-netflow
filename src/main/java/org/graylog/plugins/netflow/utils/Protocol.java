/**
 * Copyright (C) 2012, 2013, 2014 wasted.io Ltd <really@wasted.io>
 * Copyright (C) 2015 Graylog, Inc. (hello@graylog.org)
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
package org.graylog.plugins.netflow.utils;

import com.google.common.collect.ImmutableMap;

/**
 * Can be used to lookup protocol numbers. Generated from a /etc/protocols file on Ubuntu 14.04 LTS.
 */
public enum Protocol {
    IP("ip", 0, "IP"),
    // HOPOPT("hopopt", 0, "HOPOPT"),
    ICMP("icmp", 1, "ICMP"),
    IGMP("igmp", 2, "IGMP"),
    GGP("ggp", 3, "GGP"),
    IPENCAP("ipencap", 4, "IP-ENCAP"),
    ST("st", 5, "ST"),
    TCP("tcp", 6, "TCP"),
    EGP("egp", 8, "EGP"),
    IGP("igp", 9, "IGP"),
    PUP("pup", 12, "PUP"),
    UDP("udp", 17, "UDP"),
    HMP("hmp", 20, "HMP"),
    XNS_IDP("xns-idp", 22, "XNS-IDP"),
    RDP("rdp", 27, "RDP"),
    ISO_TP4("iso-tp4", 29, "ISO-TP4"),
    DCCP("dccp", 33, "DCCP"),
    XTP("xtp", 36, "XTP"),
    DDP("ddp", 37, "DDP"),
    IDPR_CMTP("idpr-cmtp", 38, "IDPR-CMTP"),
    IPV6("ipv6", 41, "IPv6"),
    IPV6_ROUTE("ipv6-route", 43, "IPv6-Route"),
    IPV6_FRAG("ipv6-frag", 44, "IPv6-Frag"),
    IDRP("idrp", 45, "IDRP"),
    RSVP("rsvp", 46, "RSVP"),
    GRE("gre", 47, "GRE"),
    ESP("esp", 50, "IPSEC-ESP"),
    AH("ah", 51, "IPSEC-AH"),
    SKIP("skip", 57, "SKIP"),
    IPV6_ICMP("ipv6-icmp", 58, "IPv6-ICMP"),
    IPV6_NONXT("ipv6-nonxt", 59, "IPv6-NoNxt"),
    IPV6_OPTS("ipv6-opts", 60, "IPv6-Opts"),
    RSPF("rspf", 73, "RSPF"),
    VMTP("vmtp", 81, "VMTP"),
    EIGRP("eigrp", 88, "EIGRP"),
    OSPF("ospf", 89, "OSPFIGP"),
    AX_25("ax.25", 93, "AX.25"),
    IPIP("ipip", 94, "IPIP"),
    ETHERIP("etherip", 97, "ETHERIP"),
    ENCAP("encap", 98, "ENCAP"),
    PIM("pim", 103, "PIM"),
    IPCOMP("ipcomp", 108, "IPCOMP"),
    VRRP("vrrp", 112, "VRRP"),
    L2TP("l2tp", 115, "L2TP"),
    ISIS("isis", 124, "ISIS"),
    SCTP("sctp", 132, "SCTP"),
    FC("fc", 133, "FC"),
    MOBILITY_HEADER("mobility-header", 135, "Mobility-Header"),
    UDPLITE("udplite", 136, "UDPLite"),
    MPLS_IN_IP("mpls-in-ip", 137, "MPLS-in-IP"),
    MANET("manet", 138, "#"),
    HIP("hip", 139, "HIP"),
    SHIM6("shim6", 140, "Shim6"),
    WESP("wesp", 141, "WESP"),
    ROHC("rohc", 142, "ROHC");

    private final String name;
    private final int number;
    private final String alias;

    private static final ImmutableMap<Integer, Protocol> ID_MAP;

    static {
        final ImmutableMap.Builder<Integer, Protocol> idMapBuilder = ImmutableMap.builder();
        for (final Protocol protocol : values()) {
            idMapBuilder.put(protocol.getNumber(), protocol);
        }
        ID_MAP = idMapBuilder.build();
    }

    Protocol(final String name, final int number, final String alias) {
        this.name = name;
        this.number = number;
        this.alias = alias;
    }

    public String getAlias() {
        return alias;
    }

    public String getName() {
        return name;
    }

    public int getNumber() {
        return number;
    }

    public static Protocol getByNumber(final int number) {
        return ID_MAP.get(number);
    }
}

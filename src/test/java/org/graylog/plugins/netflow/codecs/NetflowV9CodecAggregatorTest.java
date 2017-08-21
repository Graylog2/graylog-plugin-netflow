package org.graylog.plugins.netflow.codecs;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.io.Resources;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.pkts.Pcap;
import io.pkts.packet.UDPPacket;
import io.pkts.protocol.Protocol;
import org.graylog.plugins.netflow.v9.NetFlowV9BaseRecord;
import org.graylog.plugins.netflow.v9.NetFlowV9FieldDef;
import org.graylog.plugins.netflow.v9.NetFlowV9FieldType;
import org.graylog.plugins.netflow.v9.NetFlowV9Packet;
import org.graylog.plugins.netflow.v9.NetFlowV9Record;
import org.graylog.plugins.netflow.v9.NetFlowV9Template;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.inputs.codecs.CodecAggregator;
import org.graylog2.plugin.journal.RawMessage;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class NetflowV9CodecAggregatorTest {
    private static final Logger LOG = LoggerFactory.getLogger(NetflowV9CodecAggregatorTest.class);

    private NetFlowCodec codec;
    private NetflowV9CodecAggregator codecAggregator;
    private InetSocketAddress source;

    public NetflowV9CodecAggregatorTest() throws IOException {
        source = new InetSocketAddress(InetAddress.getLocalHost(), 12345);
    }

    @Before
    public void setup() throws IOException {
        // the codec aggregator creates "netflowv9"ish packets, that always contain all necessary templates before the data flows
        // this is not an RFC netflow packet, but greatly simplifies decoding
        codecAggregator = new NetflowV9CodecAggregator();
        final Configuration configuration = new Configuration(null);
        codec = new NetFlowCodec(configuration);
    }


    @Test
    public void pcap_netgraph_NetFlowV5() throws Exception {
        final Collection<Message> allMessages = decodePcapStream("netflow-data/netgraph-netflow5.pcap");
        assertThat(allMessages)
                .hasSize(120)
                .allSatisfy(message -> assertThat(message.getField("nf_version")).isEqualTo(5));
    }

    @Test
    public void pcap_nprobe_NetFlowV9_mixed() throws Exception {
        final Collection<Message> allMessages = decodePcapStream("netflow-data/nprobe-netflow9.pcap");
        assertThat(allMessages)
                .hasSize(152);
    }

    @Test
    public void pcap_softflowd_NetFlowV5() throws Exception {
        final Collection<Message> allMessages = decodePcapStream("netflow-data/netflow5.pcap");

        assertThat(allMessages)
                .hasSize(4)
                .allSatisfy(message -> assertThat(message.getField("nf_version")).isEqualTo(5));
    }

    @Test
    public void pcap_softflowd_NetFlowV9() throws Exception {
        final List<NetFlowV9BaseRecord> allRecords = new ArrayList<>();
        final List<NetFlowV9Template> allTemplates = new ArrayList<>();

        final Collection<NetFlowV9Packet> packets = parseNetflowPcapStream("netflow-data/netflow9.pcap");
        packets.forEach(packet -> {
            allRecords.addAll(packet.records());
            allTemplates.addAll(packet.templates());
        });

        assertThat(allTemplates).contains(
                NetFlowV9Template.create(1024, 13,
                        ImmutableList.<NetFlowV9FieldDef>builder().add(
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(8, NetFlowV9FieldType.ValueType.IPV4, "ipv4_src_addr"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(12, NetFlowV9FieldType.ValueType.IPV4, "ipv4_dst_addr"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(21, NetFlowV9FieldType.ValueType.UINT32, "last_switched"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(22, NetFlowV9FieldType.ValueType.UINT32, "first_switched"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(1, NetFlowV9FieldType.ValueType.UINT32, "in_bytes"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(2, NetFlowV9FieldType.ValueType.UINT32, "in_pkts"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(10, NetFlowV9FieldType.ValueType.UINT16, "input_snmp"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(14, NetFlowV9FieldType.ValueType.UINT16, "output_snmp"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(7, NetFlowV9FieldType.ValueType.UINT16, "l4_src_port"), 2),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(11, NetFlowV9FieldType.ValueType.UINT16, "l4_dst_port"), 2),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(4, NetFlowV9FieldType.ValueType.UINT8, "protocol"), 1),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(6, NetFlowV9FieldType.ValueType.UINT8, "tcp_flags"), 1),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(60, NetFlowV9FieldType.ValueType.UINT8, "ip_protocol_version"), 1)
                        ).build()
                )
        );
        assertThat(allRecords).hasSize(19)
                .contains(
                        NetFlowV9Record.create(
                                ImmutableMap.<String, Object>builder()
                                        .put("ipv4_src_addr", "8.8.8.8")
                                        .put("ipv4_dst_addr", "192.168.1.20")
                                        .put("last_switched", 208442L)
                                        .put("first_switched", 208442L)
                                        .put("in_bytes", 76L)
                                        .put("in_pkts", 1L)
                                        .put("input_snmp", 0L)
                                        .put("output_snmp", 0L)
                                        .put("l4_src_port", 53)
                                        .put("l4_dst_port", 34865)
                                        .put("protocol", (short) 17)
                                        .put("tcp_flags", (short) 0)
                                        .put("ip_protocol_version", (short) 4L)
                                        .build())
                );

    }

    @Test
    public void pcap_pmacctd_NetFlowV5() throws Exception {
        final Collection<Message> allMessages = decodePcapStream("netflow-data/pmacctd-netflow5.pcap");

        assertThat(allMessages)
                .hasSize(42)
                .allSatisfy(message -> assertThat(message.getField("nf_version")).isEqualTo(5));
    }

    @Test
    public void pcap_pmacctd_NetFlowV9() throws Exception {
        final List<NetFlowV9BaseRecord> allRecords = new ArrayList<>();
        final List<NetFlowV9Template> allTemplates = new ArrayList<>();
        final Collection<NetFlowV9Packet> packets = parseNetflowPcapStream("netflow-data/pmacctd-netflow9.pcap");
        packets.forEach(packet -> {
            allRecords.addAll(packet.records());
            allTemplates.addAll(packet.templates());
        });

        assertThat(allTemplates).contains(
                NetFlowV9Template.create(1024, 10,
                        ImmutableList.<NetFlowV9FieldDef>builder().add(
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(153, NetFlowV9FieldType.ValueType.UINT64, "nf_field_153"), 8),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(152, NetFlowV9FieldType.ValueType.UINT64, "flow_start_msec"), 8),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(1, NetFlowV9FieldType.ValueType.UINT32, "in_bytes"), 8),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(2, NetFlowV9FieldType.ValueType.UINT32, "in_pkts"), 8),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(60, NetFlowV9FieldType.ValueType.UINT8, "ip_protocol_version"), 1),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(10, NetFlowV9FieldType.ValueType.UINT16, "input_snmp"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(14, NetFlowV9FieldType.ValueType.UINT16, "output_snmp"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(61, NetFlowV9FieldType.ValueType.UINT8, "direction"), 1),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(8, NetFlowV9FieldType.ValueType.IPV4, "ipv4_src_addr"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(12, NetFlowV9FieldType.ValueType.IPV4, "ipv4_dst_addr"), 4)
                        ).build()
                )
        );
        assertThat(allRecords)
                .hasSize(6)
                .contains(
                        NetFlowV9Record.create(
                                ImmutableMap.<String, Object>builder()
                                        .put("nf_field_153", 1501508283491L)
                                        .put("flow_start_msec", 1501508283473L)
                                        .put("in_bytes", 68L)
                                        .put("in_pkts", 1L)
                                        .put("ip_protocol_version", (short) 4)
                                        .put("input_snmp", 0L)
                                        .put("output_snmp", 0L)
                                        .put("direction", (short) 0)
                                        .put("ipv4_src_addr", "172.17.0.2")
                                        .put("ipv4_dst_addr", "8.8.4.4")
                                        .build())
                );
    }

    @Test
    public void pcap_nprobe_NetFlowV9_2() throws Exception {
        final List<NetFlowV9BaseRecord> allRecords = new ArrayList<>();
        final List<NetFlowV9Template> allTemplates = new ArrayList<>();
        final Collection<NetFlowV9Packet> packets = parseNetflowPcapStream("netflow-data/nprobe-netflow9-2.pcap");
        packets.forEach(packet -> {
            allRecords.addAll(packet.records());
            allTemplates.addAll(packet.templates());
        });

        assertThat(allTemplates).contains(
                NetFlowV9Template.create(257, 18,
                        ImmutableList.<NetFlowV9FieldDef>builder().add(
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(1, NetFlowV9FieldType.ValueType.UINT32, "in_bytes"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(2, NetFlowV9FieldType.ValueType.UINT32, "in_pkts"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(4, NetFlowV9FieldType.ValueType.UINT8, "protocol"), 1),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(5, NetFlowV9FieldType.ValueType.UINT8, "src_tos"), 1),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(6, NetFlowV9FieldType.ValueType.UINT8, "tcp_flags"), 1),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(7, NetFlowV9FieldType.ValueType.UINT16, "l4_src_port"), 2),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(8, NetFlowV9FieldType.ValueType.IPV4, "ipv4_src_addr"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(9, NetFlowV9FieldType.ValueType.UINT8, "src_mask"), 1),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(10, NetFlowV9FieldType.ValueType.UINT16, "input_snmp"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(11, NetFlowV9FieldType.ValueType.UINT16, "l4_dst_port"), 2),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(12, NetFlowV9FieldType.ValueType.IPV4, "ipv4_dst_addr"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(13, NetFlowV9FieldType.ValueType.UINT8, "dst_mask"), 1),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(14, NetFlowV9FieldType.ValueType.UINT16, "output_snmp"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(15, NetFlowV9FieldType.ValueType.IPV4, "ipv4_next_hop"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(16, NetFlowV9FieldType.ValueType.UINT16, "src_as"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(17, NetFlowV9FieldType.ValueType.UINT16, "dst_as"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(21, NetFlowV9FieldType.ValueType.UINT32, "last_switched"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(22, NetFlowV9FieldType.ValueType.UINT32, "first_switched"), 4)
                        ).build()
                )
        );
        assertThat(allRecords)
                .hasSize(7)
                .contains(
                        NetFlowV9Record.create(
                                ImmutableMap.<String, Object>builder()
                                        .put("in_bytes", 375L)
                                        .put("in_pkts", 7L)
                                        .put("ipv4_src_addr", "172.17.0.2")
                                        .put("ipv4_dst_addr", "93.184.216.34")
                                        .put("ipv4_next_hop", "0.0.0.0")
                                        .put("l4_src_port", 43296)
                                        .put("l4_dst_port", 80)
                                        .put("protocol", (short) 6)
                                        .put("src_tos", (short) 0)
                                        .put("tcp_flags", (short) 27)
                                        .put("src_mask", (short) 0)
                                        .put("dst_mask", (short) 0)
                                        .put("input_snmp", 0L)
                                        .put("output_snmp", 0L)
                                        .put("src_as", 0L)
                                        .put("dst_as", 15133L)
                                        .put("first_switched", 3L)
                                        .put("last_switched", 413L)
                                        .build())
                        ,
                        NetFlowV9Record.create(
                                ImmutableMap.<String, Object>builder()
                                        .put("in_bytes", 1829L)
                                        .put("in_pkts", 6L)
                                        .put("ipv4_src_addr", "93.184.216.34")
                                        .put("ipv4_dst_addr", "172.17.0.2")
                                        .put("ipv4_next_hop", "0.0.0.0")
                                        .put("l4_src_port", 80)
                                        .put("l4_dst_port", 43296)
                                        .put("protocol", (short) 6)
                                        .put("src_tos", (short) 0)
                                        .put("tcp_flags", (short) 27)
                                        .put("src_mask", (short) 0)
                                        .put("dst_mask", (short) 0)
                                        .put("input_snmp", 0L)
                                        .put("output_snmp", 0L)
                                        .put("src_as", 15133L)
                                        .put("dst_as", 0L)
                                        .put("first_switched", 138L)
                                        .put("last_switched", 413L)
                                        .build()),
                        NetFlowV9Record.create(
                                ImmutableMap.<String, Object>builder()
                                        .put("in_bytes", 68L)
                                        .put("in_pkts", 1L)
                                        .put("ipv4_src_addr", "172.17.0.2")
                                        .put("ipv4_dst_addr", "8.8.4.4")
                                        .put("ipv4_next_hop", "0.0.0.0")
                                        .put("l4_src_port", 60546)
                                        .put("l4_dst_port", 53)
                                        .put("protocol", (short) 17)
                                        .put("src_tos", (short) 0)
                                        .put("tcp_flags", (short) 0)
                                        .put("src_mask", (short) 0)
                                        .put("dst_mask", (short) 0)
                                        .put("input_snmp", 0L)
                                        .put("output_snmp", 0L)
                                        .put("src_as", 0L)
                                        .put("dst_as", 15169L)
                                        .put("first_switched", 284L)
                                        .put("last_switched", 284L)
                                        .build()),
                        NetFlowV9Record.create(
                                ImmutableMap.<String, Object>builder()
                                        .put("in_bytes", 84L)
                                        .put("in_pkts", 1L)
                                        .put("ipv4_src_addr", "8.8.4.4")
                                        .put("ipv4_dst_addr", "172.17.0.2")
                                        .put("ipv4_next_hop", "0.0.0.0")
                                        .put("l4_src_port", 53)
                                        .put("l4_dst_port", 60546)
                                        .put("protocol", (short) 17)
                                        .put("src_tos", (short) 0)
                                        .put("tcp_flags", (short) 0)
                                        .put("src_mask", (short) 0)
                                        .put("dst_mask", (short) 0)
                                        .put("input_snmp", 0L)
                                        .put("output_snmp", 0L)
                                        .put("src_as", 15169L)
                                        .put("dst_as", 0L)
                                        .put("first_switched", 321L)
                                        .put("last_switched", 321L)
                                        .build())
                );
    }

    @Test
    public void pcap_nprobe_NetFlowV9_3() throws Exception {
        final List<NetFlowV9BaseRecord> allRecords = new ArrayList<>();
        final List<NetFlowV9Template> allTemplates = new ArrayList<>();

        final Collection<NetFlowV9Packet> packets = parseNetflowPcapStream("netflow-data/nprobe-netflow9-3.pcap");
        packets.forEach(packet -> {
            allRecords.addAll(packet.records());
            allTemplates.addAll(packet.templates());
        });

        assertThat(allTemplates).contains(
                NetFlowV9Template.create(257, 18,
                        ImmutableList.<NetFlowV9FieldDef>builder().add(
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(1, NetFlowV9FieldType.ValueType.UINT32, "in_bytes"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(2, NetFlowV9FieldType.ValueType.UINT32, "in_pkts"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(4, NetFlowV9FieldType.ValueType.UINT8, "protocol"), 1),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(5, NetFlowV9FieldType.ValueType.UINT8, "src_tos"), 1),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(6, NetFlowV9FieldType.ValueType.UINT8, "tcp_flags"), 1),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(7, NetFlowV9FieldType.ValueType.UINT16, "l4_src_port"), 2),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(8, NetFlowV9FieldType.ValueType.IPV4, "ipv4_src_addr"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(9, NetFlowV9FieldType.ValueType.UINT8, "src_mask"), 1),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(10, NetFlowV9FieldType.ValueType.UINT16, "input_snmp"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(11, NetFlowV9FieldType.ValueType.UINT16, "l4_dst_port"), 2),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(12, NetFlowV9FieldType.ValueType.IPV4, "ipv4_dst_addr"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(13, NetFlowV9FieldType.ValueType.UINT8, "dst_mask"), 1),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(14, NetFlowV9FieldType.ValueType.UINT16, "output_snmp"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(15, NetFlowV9FieldType.ValueType.IPV4, "ipv4_next_hop"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(16, NetFlowV9FieldType.ValueType.UINT16, "src_as"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(17, NetFlowV9FieldType.ValueType.UINT16, "dst_as"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(21, NetFlowV9FieldType.ValueType.UINT32, "last_switched"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(22, NetFlowV9FieldType.ValueType.UINT32, "first_switched"), 4)
                        ).build()
                )
        );
        assertThat(allRecords).hasSize(898);
    }

    @Test
    public void pcap_nprobe_NetFlowV9_4() throws Exception {
        final List<NetFlowV9BaseRecord> allRecords = new ArrayList<>();
        final List<NetFlowV9Template> allTemplates = new ArrayList<>();

        final Collection<NetFlowV9Packet> packets = parseNetflowPcapStream("netflow-data/nprobe-netflow9-4.pcap");
        packets.forEach(packet -> {
            allRecords.addAll(packet.records());
            allTemplates.addAll(packet.templates());
        });

        assertThat(allTemplates).contains(
                NetFlowV9Template.create(257, 18,
                        ImmutableList.<NetFlowV9FieldDef>builder().add(
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(1, NetFlowV9FieldType.ValueType.UINT32, "in_bytes"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(2, NetFlowV9FieldType.ValueType.UINT32, "in_pkts"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(4, NetFlowV9FieldType.ValueType.UINT8, "protocol"), 1),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(5, NetFlowV9FieldType.ValueType.UINT8, "src_tos"), 1),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(6, NetFlowV9FieldType.ValueType.UINT8, "tcp_flags"), 1),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(7, NetFlowV9FieldType.ValueType.UINT16, "l4_src_port"), 2),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(8, NetFlowV9FieldType.ValueType.IPV4, "ipv4_src_addr"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(9, NetFlowV9FieldType.ValueType.UINT8, "src_mask"), 1),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(10, NetFlowV9FieldType.ValueType.UINT16, "input_snmp"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(11, NetFlowV9FieldType.ValueType.UINT16, "l4_dst_port"), 2),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(12, NetFlowV9FieldType.ValueType.IPV4, "ipv4_dst_addr"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(13, NetFlowV9FieldType.ValueType.UINT8, "dst_mask"), 1),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(14, NetFlowV9FieldType.ValueType.UINT16, "output_snmp"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(15, NetFlowV9FieldType.ValueType.IPV4, "ipv4_next_hop"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(16, NetFlowV9FieldType.ValueType.UINT16, "src_as"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(17, NetFlowV9FieldType.ValueType.UINT16, "dst_as"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(21, NetFlowV9FieldType.ValueType.UINT32, "last_switched"), 4),
                                NetFlowV9FieldDef.create(NetFlowV9FieldType.create(22, NetFlowV9FieldType.ValueType.UINT32, "first_switched"), 4)
                        ).build()
                )
        );
        assertThat(allRecords).hasSize(16);
    }

    @Test
    public void decodeMessagesSuccessfullyDecodesNetFlowV5() throws Exception {
        final Collection<Message> messages = decodeResult(aggregateRawPacket("netflow-data/netflow-v5-1.dat"));
        assertThat(messages)
                .isNotNull()
                .hasSize(2);
        final Message message = Iterables.get(messages, 0);
        assertThat(message).isNotNull();

        assertThat(message.getMessage()).isEqualTo("NetFlowV5 [10.0.2.2]:54435 <> [10.0.2.15]:22 proto:6 pkts:5 bytes:230");
        assertThat(message.getTimestamp()).isEqualTo(DateTime.parse("2015-05-02T18:38:08.280Z"));
        assertThat(message.getSource()).isEqualTo(source.getAddress().getHostAddress());
        assertThat(message.getFields())
                .containsEntry("nf_src_address", "10.0.2.2")
                .containsEntry("nf_dst_address", "10.0.2.15")
                .containsEntry("nf_proto_name", "TCP")
                .containsEntry("nf_src_as", 0)
                .containsEntry("nf_dst_as", 0)
                .containsEntry("nf_snmp_input", 0)
                .containsEntry("nf_snmp_output", 0);
    }

    @Test
    public void decodeMessagesSuccessfullyDecodesNetFlowV9() throws Exception {
        final Collection<Message> messages1 = decodeResult(aggregateRawPacket("netflow-data/netflow-v9-2-1.dat"));
        final Collection<Message> messages2 = decodeResult(aggregateRawPacket("netflow-data/netflow-v9-2-2.dat"));
        final Collection<Message> messages3 = decodeResult(aggregateRawPacket("netflow-data/netflow-v9-2-3.dat"));

        assertThat(messages1).isEmpty();
        assertThat(messages2)
                .isNotNull()
                .hasSize(1);
        final Message message2 = Iterables.getFirst(messages2, null);
        assertThat(message2).isNotNull();
        assertThat(message2.getMessage()).isEqualTo("NetFlowV9 [192.168.124.1]:3072 <> [239.255.255.250]:1900 proto:17 pkts:8 bytes:2818");
        assertThat(message2.getTimestamp()).isEqualTo(DateTime.parse("2013-05-21T07:51:49.000Z"));
        assertThat(message2.getSource()).isEqualTo(source.getAddress().getHostAddress());
        assertThat(message2.getFields())
                .containsEntry("nf_src_address", "192.168.124.1")
                .containsEntry("nf_dst_address", "239.255.255.250")
                .containsEntry("nf_proto_name", "UDP")
                .containsEntry("nf_src_as", 0L)
                .containsEntry("nf_dst_as", 0L)
                .containsEntry("nf_snmp_input", 0)
                .containsEntry("nf_snmp_output", 0);

        assertThat(messages3)
                .isNotNull()
                .hasSize(1);
        final Message message3 = Iterables.getFirst(messages3, null);
        assertThat(message3).isNotNull();
        assertThat(message3.getMessage()).isEqualTo("NetFlowV9 [192.168.124.20]:42444 <> [121.161.231.32]:9090 proto:17 pkts:2 bytes:348");
        assertThat(message3.getTimestamp()).isEqualTo(DateTime.parse("2013-05-21T07:52:43.000Z"));
        assertThat(message3.getSource()).isEqualTo(source.getAddress().getHostAddress());
        assertThat(message3.getFields())
                .containsEntry("nf_src_address", "192.168.124.20")
                .containsEntry("nf_dst_address", "121.161.231.32")
                .containsEntry("nf_proto_name", "UDP")
                .containsEntry("nf_src_as", 0L)
                .containsEntry("nf_dst_as", 0L)
                .containsEntry("nf_snmp_input", 0)
                .containsEntry("nf_snmp_output", 0);
    }


    private RawMessage convertToRawMessage(CodecAggregator.Result result, SocketAddress remoteAddress) {
        final ChannelBuffer buffer = result.getMessage();
        final byte[] payload = new byte[buffer.readableBytes()];
        buffer.toByteBuffer().get(payload, buffer.readerIndex(), buffer.readableBytes());

        return new RawMessage(payload, (InetSocketAddress) remoteAddress);
    }

    private Collection<NetFlowV9Packet> parseNetflowPcapStream(String resourceName) throws IOException {
        final List<NetFlowV9Packet> allPackets = Lists.newArrayList();
        try (InputStream inputStream = Resources.getResource(resourceName).openStream()) {
            final Pcap pcap = Pcap.openStream(inputStream);
            pcap.loop(packet -> {
                        if (packet.hasProtocol(Protocol.UDP)) {
                            final UDPPacket udp = (UDPPacket) packet.getPacket(Protocol.UDP);
                            final InetSocketAddress source = new InetSocketAddress(udp.getSourceIP(), udp.getSourcePort());
                            final CodecAggregator.Result result = codecAggregator.addChunk(ChannelBuffers.copiedBuffer(udp.getPayload().getArray()), source);
                            if (result.isValid() && result.getMessage() != null) {
                                final ByteBuf buffer = Unpooled.wrappedBuffer(result.getMessage().toByteBuffer());
                                // must read the marker byte off the buffer first.
                                buffer.readByte();
                                allPackets.addAll(codec.decodeV9Packets(buffer));
                            }
                        }
                        return true;
                    }
            );
        }
        return allPackets;
    }

    private Collection<Message> decodePcapStream(String resourceName) throws IOException {

        final List<Message> allMessages = Lists.newArrayList();
        try (InputStream inputStream = Resources.getResource(resourceName).openStream()) {
            final Pcap pcap = Pcap.openStream(inputStream);
            pcap.loop(packet -> {
                        if (packet.hasProtocol(Protocol.UDP)) {
                            final UDPPacket udp = (UDPPacket) packet.getPacket(Protocol.UDP);
                            final InetSocketAddress source = new InetSocketAddress(udp.getSourceIP(), udp.getSourcePort());
                            final CodecAggregator.Result result = codecAggregator.addChunk(ChannelBuffers.copiedBuffer(udp.getPayload().getArray()), source);
                            if (result.isValid() && result.getMessage() != null) {
                                final Collection<Message> c = codec.decodeMessages(convertToRawMessage(result, source));
                                if (c != null) {
                                    allMessages.addAll(c);
                                }
                            }
                        }
                        return true;
                    }
            );
        }
        return allMessages;
    }


    private CodecAggregator.Result aggregateRawPacket(String resourceName) throws IOException {
        final byte[] bytes = Resources.toByteArray(Resources.getResource(resourceName));
        final ChannelBuffer channelBuffer = ChannelBuffers.wrappedBuffer(bytes);
        return codecAggregator.addChunk(channelBuffer, source);
    }

    private Collection<Message> decodeResult(CodecAggregator.Result result) {
        if (result.getMessage() == null) {
            return Collections.emptyList();
        }
        return codec.decodeMessages(convertToRawMessage(result, source));
    }
}
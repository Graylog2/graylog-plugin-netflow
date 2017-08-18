package org.graylog.plugins.netflow.codecs;

import com.google.common.collect.ImmutableMap;
import com.google.common.io.Resources;
import io.pkts.Pcap;
import io.pkts.packet.UDPPacket;
import io.pkts.protocol.Protocol;
import org.graylog.plugins.netflow.flows.FlowException;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.journal.RawMessage;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

public class NetFlowCodecTest {
    @Rule
    public final TemporaryFolder temporaryFolder = new TemporaryFolder();

    private NetFlowCodec codec;

    @Before
    public void setUp() throws Exception {
        final ImmutableMap<String, Object> configMap = ImmutableMap.of();
        final Configuration configuration = new Configuration(configMap);

        codec = new NetFlowCodec(configuration);
    }

    @Test
    public void constructorFailsIfNetFlow9DefinitionsPathDoesNotExist() throws Exception {
        final File definitionsFile = temporaryFolder.newFile();
        assertThat(definitionsFile.delete()).isTrue();

        final ImmutableMap<String, Object> configMap = ImmutableMap.of(
                NetFlowCodec.CK_NETFLOW9_DEFINITION_PATH, definitionsFile.getAbsolutePath());
        final Configuration configuration = new Configuration(configMap);

        assertThatExceptionOfType(FileNotFoundException.class)
                .isThrownBy(() -> new NetFlowCodec(configuration))
                .withMessageEndingWith("(No such file or directory)");
    }

    @Test
    public void constructorSucceedsIfNetFlow9DefinitionsPathIsEmpty() throws Exception {
        final ImmutableMap<String, Object> configMap = ImmutableMap.of(
                NetFlowCodec.CK_NETFLOW9_DEFINITION_PATH, "");
        final Configuration configuration = new Configuration(configMap);

        assertThat(new NetFlowCodec(configuration)).isNotNull();
    }

    @Test
    public void constructorSucceedsIfNetFlow9DefinitionsPathIsBlank() throws Exception {
        final ImmutableMap<String, Object> configMap = ImmutableMap.of(
                NetFlowCodec.CK_NETFLOW9_DEFINITION_PATH, "   ");
        final Configuration configuration = new Configuration(configMap);

        assertThat(new NetFlowCodec(configuration)).isNotNull();
    }

    @Test
    public void constructorFailsIfNetFlow9DefinitionsPathIsInvalidYaml() throws Exception {
        final File definitionsFile = temporaryFolder.newFile();
        Files.write(definitionsFile.toPath(), "foo: %bar".getBytes(StandardCharsets.UTF_8));

        final ImmutableMap<String, Object> configMap = ImmutableMap.of(
                NetFlowCodec.CK_NETFLOW9_DEFINITION_PATH, definitionsFile.getAbsolutePath());
        final Configuration configuration = new Configuration(configMap);

        assertThatIllegalArgumentException()
                .isThrownBy(() -> new NetFlowCodec(configuration))
                .withMessageMatching("Unable to parse NetFlow 9 definitions");
    }

    @Test
    public void decodeThrowsUnsupportedOperationException() throws Exception {
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> codec.decode(new RawMessage(new byte[0])))
                .withMessage("MultiMessageCodec " + NetFlowCodec.class + " does not support decode()");
    }

    @Test
    public void decodeMessagesReturnsNullIfMessageWasInvalid() throws Exception {
        final byte[] b = "Foobar".getBytes(StandardCharsets.UTF_8);
        final InetSocketAddress source = new InetSocketAddress(InetAddress.getLocalHost(), 12345);
        final RawMessage rawMessage = new RawMessage(b, source);

        final Collection<Message> messages = codec.decodeMessages(rawMessage);
        assertThat(messages).isNull();
    }

    @Test
    public void decodeMessagesReturnsNullIfNetFlowParserThrowsFlowException() throws Exception {
        final byte[] b = "Foobar".getBytes(StandardCharsets.UTF_8);
        final InetSocketAddress source = new InetSocketAddress(InetAddress.getLocalHost(), 12345);
        final RawMessage rawMessage = new RawMessage(b, source) {
            private boolean triggered = false;
            @Override
            public byte[] getPayload() {
                if (triggered) {
                    return new byte[]{};
                }
                triggered = true;
                throw new FlowException("Boom!");
            }
        };

        final Collection<Message> messages = codec.decodeMessages(rawMessage);
        assertThat(messages).isNull();
    }

    @Test
    public void decodeMessagesThrowsEmptyTemplateExceptionWithIncompleteNetFlowV9() throws Exception {
        final byte[] b = Resources.toByteArray(Resources.getResource("netflow-data/netflow-v9-3_incomplete.dat"));
        final InetSocketAddress source = new InetSocketAddress(InetAddress.getLocalHost(), 12345);

        assertThat(codec.decodeMessages(new RawMessage(b, source))).isNull();
    }

    @Test
    public void pcap_softflowd_NetFlowV5() throws Exception {
        final List<Message> allMessages = new ArrayList<>();
        try (InputStream inputStream = Resources.getResource("netflow-data/netflow5.pcap").openStream()) {
            final Pcap pcap = Pcap.openStream(inputStream);
            pcap.loop(packet -> {
                        if (packet.hasProtocol(Protocol.UDP)) {
                            final UDPPacket udp = (UDPPacket) packet.getPacket(Protocol.UDP);
                            final InetSocketAddress source = new InetSocketAddress(udp.getSourceIP(), udp.getSourcePort());
                            final Collection<Message> messages = codec.decodeMessages(new RawMessage(udp.getPayload().getArray(), source));
                            assertThat(messages)
                                    .isNotNull()
                                    .isNotEmpty();
                            allMessages.addAll(messages);
                        }
                        return true;
                    }
            );
            assertThat(allMessages)
                    .hasSize(4)
                    .allSatisfy(message -> assertThat(message.getField("nf_version")).isEqualTo(5));
        }
    }

    @Test
    public void pcap_pmacctd_NetFlowV5() throws Exception {
        final List<Message> allMessages = new ArrayList<>();
        try (InputStream inputStream = Resources.getResource("netflow-data/pmacctd-netflow5.pcap").openStream()) {
            final Pcap pcap = Pcap.openStream(inputStream);
            pcap.loop(packet -> {
                        if (packet.hasProtocol(Protocol.UDP)) {
                            final UDPPacket udp = (UDPPacket) packet.getPacket(Protocol.UDP);
                            final InetSocketAddress source = new InetSocketAddress(udp.getSourceIP(), udp.getSourcePort());
                            final Collection<Message> messages = codec.decodeMessages(new RawMessage(udp.getPayload().getArray(), source));
                            assertThat(messages)
                                    .isNotNull()
                                    .isNotEmpty();
                            allMessages.addAll(messages);
                        }
                        return true;
                    }
            );
            assertThat(allMessages)
                    .hasSize(42)
                    .allSatisfy(message -> assertThat(message.getField("nf_version")).isEqualTo(5));;
        }
    }

    @Test
    public void pcap_softflowd_NetFlowV9() throws Exception {
        final List<Message> allMessages = new ArrayList<>();
        try (InputStream inputStream = Resources.getResource("netflow-data/netflow9.pcap").openStream()) {
            final Pcap pcap = Pcap.openStream(inputStream);
            pcap.loop(packet -> {
                        if (packet.hasProtocol(Protocol.UDP)) {
                            final UDPPacket udp = (UDPPacket) packet.getPacket(Protocol.UDP);
                            final InetSocketAddress source = new InetSocketAddress(udp.getSourceIP(), udp.getSourcePort());
                            final Collection<Message> messages = codec.decodeMessages(new RawMessage(udp.getPayload().getArray(), source));
                            assertThat(messages)
                                    .isNotNull()
                                    .isNotEmpty();
                            allMessages.addAll(messages);
                        }
                        return true;
                    }
            );
        }
        assertThat(allMessages)
                .hasSize(19)
                .allSatisfy(message -> assertThat(message.getField("nf_version")).isEqualTo(9));;
    }

    @Test
    public void pcap_pmacctd_NetFlowV9() throws Exception {
        final List<Message> allMessages = new ArrayList<>();
        try (InputStream inputStream = Resources.getResource("netflow-data/pmacctd-netflow9.pcap").openStream()) {
            final Pcap pcap = Pcap.openStream(inputStream);
            pcap.loop(packet -> {
                        if (packet.hasProtocol(Protocol.UDP)) {
                            final UDPPacket udp = (UDPPacket) packet.getPacket(Protocol.UDP);
                            final InetSocketAddress source = new InetSocketAddress(udp.getSourceIP(), udp.getSourcePort());
                            final Collection<Message> messages = codec.decodeMessages(new RawMessage(udp.getPayload().getArray(), source));
                            assertThat(messages)
                                    .isNotNull()
                                    .isNotEmpty();
                            allMessages.addAll(messages);
                        }
                        return true;
                    }
            );
        }
        assertThat(allMessages)
                .hasSize(6)
                .allSatisfy(message -> assertThat(message.getField("nf_version")).isEqualTo(9));;
    }

    @Test
    public void pcap_netgraph_NetFlowV5() throws Exception {
        final List<Message> allMessages = new ArrayList<>();
        try (InputStream inputStream = Resources.getResource("netflow-data/netgraph-netflow5.pcap").openStream()) {
            final Pcap pcap = Pcap.openStream(inputStream);
            pcap.loop(packet -> {
                        if (packet.hasProtocol(Protocol.UDP)) {
                            final UDPPacket udp = (UDPPacket) packet.getPacket(Protocol.UDP);
                            final InetSocketAddress source = new InetSocketAddress(udp.getSourceIP(), udp.getSourcePort());
                            final Collection<Message> messages = codec.decodeMessages(new RawMessage(udp.getPayload().getArray(), source));
                            assertThat(messages)
                                    .isNotNull()
                                    .isNotEmpty();
                            allMessages.addAll(messages);
                        }
                        return true;
                    }
            );
        }
        assertThat(allMessages)
                .hasSize(120)
                .allSatisfy(message -> assertThat(message.getField("nf_version")).isEqualTo(5));
    }

    @Test
    public void pcap_nprobe_NetFlowV9_mixed() throws Exception {
        final List<Message> allMessages = new ArrayList<>();
        try (InputStream inputStream = Resources.getResource("netflow-data/nprobe-netflow9.pcap").openStream()) {
            final Pcap pcap = Pcap.openStream(inputStream);
            pcap.loop(packet -> {
                        if (packet.hasProtocol(Protocol.UDP)) {
                            final UDPPacket udp = (UDPPacket) packet.getPacket(Protocol.UDP);
                            final InetSocketAddress source = new InetSocketAddress(udp.getSourceIP(), udp.getSourcePort());
                            final Collection<Message> messages = codec.decodeMessages(new RawMessage(udp.getPayload().getArray(), source));
                            assertThat(messages).isNotNull();
                            allMessages.addAll(messages);
                        }
                        return true;
                    }
            );
        }
        assertThat(allMessages)
                .hasSize(152);
    }

    @Test
    public void pcap_nprobe_NetFlowV9_2() throws Exception {
        final List<Message> allMessages = new ArrayList<>();
        try (InputStream inputStream = Resources.getResource("netflow-data/nprobe-netflow9-2.pcap").openStream()) {
            final Pcap pcap = Pcap.openStream(inputStream);
            pcap.loop(packet -> {
                        if (packet.hasProtocol(Protocol.UDP)) {
                            final UDPPacket udp = (UDPPacket) packet.getPacket(Protocol.UDP);
                            final InetSocketAddress source = new InetSocketAddress(udp.getSourceIP(), udp.getSourcePort());
                            final Collection<Message> messages = codec.decodeMessages(new RawMessage(udp.getPayload().getArray(), source));
                            assertThat(messages).isNotNull();
                            allMessages.addAll(messages);
                        }
                        return true;
                    }
            );
        }
        assertThat(allMessages)
                .hasSize(6)
                .allSatisfy(message -> assertThat(message.getField("nf_version")).isEqualTo(9));
    }

    @Test
    public void pcap_nprobe_NetFlowV9_4() throws Exception {
        final List<Message> allMessages = new ArrayList<>();
        try (InputStream inputStream = Resources.getResource("netflow-data/nprobe-netflow9-4.pcap").openStream()) {
            final Pcap pcap = Pcap.openStream(inputStream);
            pcap.loop(packet -> {
                        if (packet.hasProtocol(Protocol.UDP)) {
                            final UDPPacket udp = (UDPPacket) packet.getPacket(Protocol.UDP);
                            final InetSocketAddress source = new InetSocketAddress(udp.getSourceIP(), udp.getSourcePort());
                            final Collection<Message> messages = codec.decodeMessages(new RawMessage(udp.getPayload().getArray(), source));
                            if (messages != null) {
                                allMessages.addAll(messages);
                            }
                        }
                        return true;
                    }
            );
        }
        assertThat(allMessages)
                .hasSize(1)
                .allSatisfy(message -> assertThat(message.getField("nf_version")).isEqualTo(9));
    }
}
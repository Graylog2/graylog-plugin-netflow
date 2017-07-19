package org.graylog.plugins.netflow.flows;

import com.google.common.collect.Iterables;
import com.google.common.io.Resources;
import org.graylog.plugins.netflow.codecs.TemplateStore;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.journal.RawMessage;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class NetFlowParserTest {
    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void parseReturnsNullIfMessageWasInvalid() throws Exception {
        final byte[] b = "Foobar".getBytes(StandardCharsets.UTF_8);
        final InetSocketAddress source = new InetSocketAddress(InetAddress.getLocalHost(), 12345);
        final RawMessage rawMessage = new RawMessage(b, source);

        final NetFlowPacket netFlowPacket = NetFlowParser.parse(rawMessage, new TemplateStore());
        assertThat(netFlowPacket).isNull();
    }

    @Test
    public void parsePropagatesFlowException() throws Exception {
        final byte[] b = "Foobar".getBytes(StandardCharsets.UTF_8);
        final InetSocketAddress source = new InetSocketAddress(InetAddress.getLocalHost(), 12345);
        final RawMessage rawMessage = new RawMessage(b, source) {
            @Override
            public byte[] getPayload() {
                throw new FlowException("Boom!");
            }
        };

        assertThatExceptionOfType(FlowException.class)
                .isThrownBy(()-> NetFlowParser.parse(rawMessage, new TemplateStore()))
                .withMessage("Boom!");
    }

    @Test
    public void parseSuccessfullyDecodesNetFlowV5() throws Exception {
        final byte[] b = Resources.toByteArray(Resources.getResource("netflow-data/netflow-v5-1.dat"));
        final InetSocketAddress source = new InetSocketAddress(InetAddress.getLocalHost(), 12345);
        final RawMessage rawMessage = new RawMessage(b, source);

        final NetFlowPacket netFlowPacket = NetFlowParser.parse(rawMessage, new TemplateStore());
        assertThat(netFlowPacket).isNotNull();
        assertThat(netFlowPacket.getFlows()).hasSize(2);

        final NetFlow netFlow1 = Iterables.get(netFlowPacket.getFlows(), 0);
        final Message message1 = netFlow1.toMessage();
        assertThat(message1).isNotNull();

        assertThat(message1.getMessage()).isEqualTo("NetFlowV5 [10.0.2.2]:54435 <> [10.0.2.15]:22 proto:6 pkts:5 bytes:230");
        assertThat(message1.getTimestamp()).isEqualTo(new DateTime(2015, 5, 2, 18, 38, 8, DateTimeZone.UTC));
        assertThat(message1.getSource()).isEqualTo(source.getAddress().getHostAddress());
        assertThat(message1.getFields())
                .containsEntry("nf_src_address", "10.0.2.2")
                .containsEntry("nf_dst_address", "10.0.2.15")
                .containsEntry("nf_proto_name", "TCP");
    }

    @Test
    public void parseSuccessfullyDecodesNetFlowV9() throws Exception {
        final byte[] b = Resources.toByteArray(Resources.getResource("netflow-data/netflow-v9-2-1.dat"));
        final InetSocketAddress source = new InetSocketAddress(InetAddress.getLocalHost(), 12345);
        final RawMessage rawMessage = new RawMessage(b, source);

        final NetFlowPacket netFlowPacket = NetFlowParser.parse(rawMessage, new TemplateStore());
        assertThat(netFlowPacket).isNotNull();
        assertThat(netFlowPacket.getFlows()).hasSize(2);

        final NetFlow netFlow1 = Iterables.get(netFlowPacket.getFlows(), 0);
        final Message message = netFlow1.toMessage();
        assertThat(message).isNotNull();

        assertThat(message.getSource()).isEqualTo(source.getAddress().getHostAddress());
    }

}
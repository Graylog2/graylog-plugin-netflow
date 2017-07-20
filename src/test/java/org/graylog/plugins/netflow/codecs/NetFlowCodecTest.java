package org.graylog.plugins.netflow.codecs;

import com.google.common.collect.Iterables;
import com.google.common.io.Resources;
import org.graylog.plugins.netflow.flows.FlowException;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.journal.RawMessage;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class NetFlowCodecTest {
    private NetFlowCodec codec;

    @Before
    public void setUp() throws Exception {
        codec = new NetFlowCodec(Configuration.EMPTY_CONFIGURATION);
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
            @Override
            public byte[] getPayload() {
                throw new FlowException("Boom!");
            }
        };

        final Collection<Message> messages = codec.decodeMessages(rawMessage);
        assertThat(messages).isNull();
    }

    @Test
    public void decodeMessagesSuccessfullyDecodesNetFlowV5() throws Exception {
        final byte[] b = Resources.toByteArray(Resources.getResource("netflow-data/netflow-v5-1.dat"));
        final InetSocketAddress source = new InetSocketAddress(InetAddress.getLocalHost(), 12345);
        final RawMessage rawMessage = new RawMessage(b, source);

        final Collection<Message> messages = codec.decodeMessages(rawMessage);
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
                .containsEntry("nf_proto_name", "TCP");
    }

    @Test
    public void decodeMessagesSuccessfullyDecodesNetFlowV9() throws Exception {
        final byte[] b1 = Resources.toByteArray(Resources.getResource("netflow-data/netflow-v9-2-1.dat"));
        final byte[] b2 = Resources.toByteArray(Resources.getResource("netflow-data/netflow-v9-2-2.dat"));
        final byte[] b3 = Resources.toByteArray(Resources.getResource("netflow-data/netflow-v9-2-3.dat"));
        final InetSocketAddress source = new InetSocketAddress(InetAddress.getLocalHost(), 12345);

        final Collection<Message> messages1 = codec.decodeMessages(new RawMessage(b1, source));
        assertThat(messages1).isEmpty();
        final Collection<Message> messages2 = codec.decodeMessages(new RawMessage(b2, source));
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
                .containsEntry("nf_proto_name", "UDP");

        final Collection<Message> messages3 = codec.decodeMessages(new RawMessage(b3, source));
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
                .containsEntry("nf_proto_name", "UDP");
    }
}
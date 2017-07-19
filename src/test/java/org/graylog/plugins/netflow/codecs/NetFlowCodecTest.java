package org.graylog.plugins.netflow.codecs;

import com.google.common.collect.Iterables;
import com.google.common.io.Resources;
import org.graylog.plugins.netflow.flows.FlowException;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.journal.RawMessage;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Ignore;
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
                .isNotEmpty();
        final Message message = Iterables.getFirst(messages, null);
        assertThat(message).isNotNull();

        assertThat(message.getMessage()).isEqualTo("NetFlowV5 [10.0.2.2]:54435 <> [10.0.2.15]:22 proto:6 pkts:5 bytes:230");
        assertThat(message.getTimestamp()).isEqualTo(new DateTime(2015, 5, 2, 18, 38, 8, DateTimeZone.UTC));
        assertThat(message.getSource()).isEqualTo(source.getAddress().getHostAddress());
        assertThat(message.getFields())
                .containsEntry("nf_src_address", "10.0.2.2")
                .containsEntry("nf_dst_address", "10.0.2.15")
                .containsEntry("nf_proto_name", "TCP");
    }

    @Test
    public void decodeMessagesSuccessfullyDecodesNetFlowV9() throws Exception {
        final byte[] b = Resources.toByteArray(Resources.getResource("netflow-data/netflow-v9-2-1.dat"));
        final InetSocketAddress source = new InetSocketAddress(InetAddress.getLocalHost(), 12345);
        final RawMessage rawMessage = new RawMessage(b, source);

        final Collection<Message> messages = codec.decodeMessages(rawMessage);
        assertThat(messages)
                .isNotNull()
                .isNotEmpty();
        final Message message = Iterables.getFirst(messages, null);
        assertThat(message).isNotNull();

        assertThat(message.getSource()).isEqualTo(source.getAddress().getHostAddress());
    }
}
package org.graylog.plugins.netflow.codecs;

import com.google.common.io.Resources;
import org.graylog.plugins.netflow.v9.NetFlowV9FieldTypeRegistry;
import org.graylog2.plugin.inputs.codecs.CodecAggregator;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.junit.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import static org.assertj.core.api.Assertions.assertThat;

public class NetflowV9CodecAggregatorTest {

    @Test
    public void netflowV9() throws Exception {
        final byte[] b1 = Resources.toByteArray(Resources.getResource("netflow-data/netflow-v9-2-1.dat"));
        final byte[] b2 = Resources.toByteArray(Resources.getResource("netflow-data/netflow-v9-2-2.dat"));
        final byte[] b3 = Resources.toByteArray(Resources.getResource("netflow-data/netflow-v9-2-3.dat"));
        final InetSocketAddress source = new InetSocketAddress(InetAddress.getLocalHost(), 12345);

        final ChannelBuffer buf1 = ChannelBuffers.wrappedBuffer(b1);
        final ChannelBuffer buf2 = ChannelBuffers.wrappedBuffer(b2);
        final ChannelBuffer buf3 = ChannelBuffers.wrappedBuffer(b3);

        final NetflowV9CodecAggregator codecAggregator = new NetflowV9CodecAggregator(NetFlowV9FieldTypeRegistry.create());

        final CodecAggregator.Result result1 = codecAggregator.addChunk(buf1, source);
        final CodecAggregator.Result result2 = codecAggregator.addChunk(buf2, source);
        final CodecAggregator.Result result3 = codecAggregator.addChunk(buf3, source);

        assertThat(result1.isValid()).isTrue();
    }
}
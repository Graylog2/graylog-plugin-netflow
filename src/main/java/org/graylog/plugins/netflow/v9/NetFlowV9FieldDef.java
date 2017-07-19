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

import com.google.auto.value.AutoValue;
import io.netty.buffer.ByteBuf;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Optional;

@AutoValue
public abstract class NetFlowV9FieldDef {
    public abstract NetFlowV9FieldType type();

    public abstract int length();

    public static NetFlowV9FieldDef create(NetFlowV9FieldType type, int length) {
        return new AutoValue_NetFlowV9FieldDef(type, length);
    }

    public Optional<Object> parse(ByteBuf bb) {
        int len = type().defaultLength;
        if (length() != 0) {
            len = length();
        }

        switch (type().valueType) {
            case INT:
                return Optional.of(parseInt(bb, len));
            case LONG:
                return Optional.of(parseLong(bb, len));
            case IPV4:
                byte[] b = new byte[4];
                bb.readBytes(b);
                try {
                    return Optional.of(InetAddress.getByAddress(b).getHostAddress());
                } catch (UnknownHostException e) {
                    return Optional.empty();
                }
            case IPV6:
                byte[] b2 = new byte[16];
                bb.readBytes(b2);
                try {
                    return Optional.of(InetAddress.getByAddress(b2).getHostAddress());
                } catch (UnknownHostException e) {
                    return Optional.empty();
                }
            case MAC:
                byte[] b3 = new byte[6];
                bb.readBytes(b3);
                return Optional.of(String.format("%02x:%02x:%02x:%02x:%02x:%02x", b3[0], b3[1], b3[2], b3[3], b3[4], b3[5]));
            case STRING:
                byte[] b4 = new byte[len];
                bb.readBytes(b4);
                return Optional.of(new String(b4));
            default:
                return Optional.empty();
        }
    }

    private int parseInt(ByteBuf bb, int length) {
        int l = 0;
        for (int i = 0; i < length; i++) {
            l <<= 8;
            l |= bb.readUnsignedByte();
        }
        return l;
    }

    private long parseLong(ByteBuf bb, int length) {
        long l = 0;
        for (int i = 0; i < length; i++) {
            l <<= 8;
            l |= bb.readUnsignedByte();
        }
        return l;
    }
}
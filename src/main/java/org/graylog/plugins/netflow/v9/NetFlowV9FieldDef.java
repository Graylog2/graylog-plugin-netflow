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

import io.netty.buffer.ByteBuf;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * @since 0.1.0
 * @author xeraph
 */
public class NetFlowV9FieldDef {
    private NetFlowV9FieldType type;
    private int length;

    public NetFlowV9FieldDef(NetFlowV9FieldType type, int length) {
        this.type = type;
        this.length = length;
    }

    public Object parse(ByteBuf bb) {
        int len = type.defaultLength;
        if (length != 0)
            len = length;

        switch (type.valueType) {
            case 1:
                return parseInt(bb, len);
            case 2:
                return parseLong(bb, len);
            case 3:
                byte[] b = new byte[4];
                bb.readBytes(b);
                try {
                    return InetAddress.getByAddress(b).getHostAddress();
                } catch (UnknownHostException e) {
                    return null;
                }
            case 4:
                byte[] b2 = new byte[16];
                bb.readBytes(b2);
                try {
                    return InetAddress.getByAddress(b2).getHostAddress();
                } catch (UnknownHostException e) {
                    return null;
                }
            case 5:
                byte[] b3 = new byte[6];
                bb.readBytes(b3);
                return String.format("%02x:%02x:%02x:%02x:%02x:%02x", b3[0], b3[1], b3[2], b3[3], b3[4], b3[5]);
            case 6:
                byte[] b4 = new byte[len];
                bb.readBytes(b4);
                return new String(b4);
            default:
                return null;
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

    public NetFlowV9FieldType getType() {
        return type;
    }

    public void setType(NetFlowV9FieldType type) {
        this.type = type;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    @Override
    public String toString() {
        return "(" + type.name().toLowerCase() + ", len=" + length + ")";
    }

}

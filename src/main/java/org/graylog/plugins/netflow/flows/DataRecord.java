/**
 * Copyright (C) 2012, 2013, 2014 wasted.io Ltd <really@wasted.io>
 * Copyright (C) 2015 Graylog, Inc. (hello@graylog.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
* Created by Benjamin H. Klimkowski, bhklimk@gmail.com
*/
package org.graylog.plugins.netflow.flows;

import com.google.common.base.MoreObjects;
import org.graylog.plugins.netflow.codecs.TemplateStore;
import org.graylog2.plugin.Message;
import org.joda.time.DateTime;

import javax.annotation.Nullable;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.UUID;


public class DataRecord extends Record {
    private List<Fieldv9> dataList;
    private TemplateStore templates;
    private InetSocketAddress sender;
    private DateTime timestamp;
    private UUID uuid;
    private InetAddress srcAddress = InetAddress.getLoopbackAddress(); //8 -> IPv4 or 27 -> IPv6
    private int srcPort = 0; //7
    private InetAddress dstAddress = InetAddress.getLoopbackAddress();  //12 -> IPv4 28 --> IPv6
    private int dstPort = 0; //11
    private int proto = 0; //4
    private int pkts = 0; //2
    private int bytes = 0; //1

    //This class provides much of the functionality of NetflowV5 class
    //that represented a single flow.  The structure is much different
    //because the flow info could be anything!


    public DataRecord(UUID id, InetSocketAddress source, DateTime ts, List<Fieldv9> dataList, TemplateStore v9templates) {
        //Constructor sets references to v9 map
        this.uuid = id;
        this.sender = source;
        this.timestamp = ts;
        this.dataList = dataList;
        this.templates = v9templates;
    }


    @Override
    @Nullable
    public Message toMessage() {
        final String source = sender.getAddress().getHostAddress();
        final Message message = new Message(toMessageString(), source, timestamp);
        for (Fieldv9 data : dataList) {
            message.addField(templates.getStringOrElse(data.getFieldType(), Integer.toString(data.getFieldType())), data.getValue());
        }
        return message;
    }

    @Override
    public String toMessageString() {
        return "NetflowV9";
    }

    @Override
    public String toString() {
        MoreObjects.ToStringHelper ans = MoreObjects.toStringHelper(this).add("uuid", uuid).add("sender", sender);
        for (Fieldv9 data : dataList) {
            ans.add(templates.getString(data.getFieldType()), data.getValueAsString());
        }
        return ans.toString();

    }

    @Override
    public String messageType() {
        return "DATA";
    }

}

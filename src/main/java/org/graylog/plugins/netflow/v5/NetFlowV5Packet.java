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
package org.graylog.plugins.netflow.v5;

import java.util.ArrayList;
import java.util.List;

/**
 * {@link http
 * ://www.cisco.com/en/US/docs/net_mgmt/netflow_collection_engine/3.6/
 * user/guide/format.html}
 * 
 * @since 0.1.0
 * @author xeraph
 * 
 */
public class NetFlowV5Packet {
	private NetFlowV5Header header;
	private List<NetFlowV5Record> records = new ArrayList<NetFlowV5Record>(50);
	private long dataLength;

	public NetFlowV5Packet() {
	}

	public NetFlowV5Packet(NetFlowV5Header header, List<NetFlowV5Record> records, long dataLength) {
		this.header = header;
		this.records = records;
		this.dataLength = dataLength;
	}

	public NetFlowV5Header getHeader() {
		return header;
	}

	public void setHeader(NetFlowV5Header header) {
		this.header = header;
	}

	public List<NetFlowV5Record> getRecords() {
		return records;
	}

	public void setRecords(List<NetFlowV5Record> records) {
		this.records = records;
	}

	public long getDataLength() {
		return dataLength;
	}

	public void setDataLength(long dataLength) {
		this.dataLength = dataLength;
	}

	@Override
	public String toString() {
		return header.toString();
	}
}

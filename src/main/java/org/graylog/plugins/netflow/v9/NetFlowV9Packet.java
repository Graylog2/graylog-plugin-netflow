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

import java.util.ArrayList;
import java.util.List;

/**
 * @since 0.1.0
 * @author xeraph
 */
public class NetFlowV9Packet {
	private NetFlowV9Header header;
	private List<NetFlowV9Template> templates = new ArrayList<NetFlowV9Template>();
	private NetFlowV9OptionTemplate optionTemplate;
	private List<NetFlowV9Record> records = new ArrayList<NetFlowV9Record>();
	private long dataLength;

	public NetFlowV9Header getHeader() {
		return header;
	}

	public void setHeader(NetFlowV9Header header) {
		this.header = header;
	}

	public List<NetFlowV9Template> getTemplates() {
		return templates;
	}

	public void setTemplates(List<NetFlowV9Template> templates) {
		this.templates = templates;
	}

	public NetFlowV9OptionTemplate getOptionTemplate() {
		return optionTemplate;
	}

	public void setOptionTemplate(NetFlowV9OptionTemplate optionTemplate) {
		this.optionTemplate = optionTemplate;
	}

	public List<NetFlowV9Record> getRecords() {
		return records;
	}

	public void setRecords(List<NetFlowV9Record> records) {
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

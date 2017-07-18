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

/**
 * {@link http://www.cisco.com/en/US/technologies/tk648/tk362/
 * technologies_white_paper09186a00800a3db9_ps6601_Products_White_Paper.html}
 * 
 * @since 0.1.0
 * @author xeraph
 * 
 */
public class NetFlowV9Header {
	// 2bytes, 9
	private int version;

	// 2bytes, both template and flow count
	private int count;

	// 4bytes
	private long sysUptime;

	// 4bytes, seconds since 0000 Coordinated Universal Time (UTC) 1970
	private long unixSecs;

	// 4bytes, Incremental sequence counter of all export packets sent by this
	// export device; this value is cumulative, and it can be used to identify
	// whether any export packets have been missed
	private long sequence;

	// 4bytes
	private long sourceId;

	public int getVersion() {
		return version;
	}

	public void setVersion(int version) {
		this.version = version;
	}

	public int getCount() {
		return count;
	}

	public void setCount(int count) {
		this.count = count;
	}

	public long getSysUptime() {
		return sysUptime;
	}

	public void setSysUptime(long sysUptime) {
		this.sysUptime = sysUptime;
	}

	public long getUnixSecs() {
		return unixSecs;
	}

	public void setUnixSecs(long unixSecs) {
		this.unixSecs = unixSecs;
	}

	public long getSequence() {
		return sequence;
	}

	public void setSequence(long sequence) {
		this.sequence = sequence;
	}

	public long getSourceId() {
		return sourceId;
	}

	public void setSourceId(long sourceId) {
		this.sourceId = sourceId;
	}

	@Override
	public String toString() {
		return "ver=" + version + ", count=" + count + ", sys_uptime=" + sysUptime + ", unixsecs=" + unixSecs + ", seq="
				+ sequence + ", source=" + sourceId;
	}
}

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

import java.util.HashMap;
import java.util.Map;

/**
 * @since 0.1.0
 * @author xeraph
 */
public class NetFlowV5Header {

	// bytes 0-1
	private int version;

	// bytes 2-3
	private int count;

	// bytes 4-7, milliseconds since device boot
	private long sysUptime;

	// bytes 8-11, seconds since UTC 1970
	private long unixSecs;

	// bytes 12-15, nanoseconds since UTC 1970
	private long unixNsecs;

	// bytes 16-19, sequence counter of total flow seen
	private long flowSequence;

	// bytes 20, type of flow switching engine
	private int engineType;

	// bytes 21, slot number of the flow-switching engine
	private int engineId;

	// bytes 22-23, first two bits hold the sampling mode, remaining 14 bits
	// hold value of sampling interval
	private int samplingMode;

	private int samplingInterval;

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

	public long getUnixNsecs() {
		return unixNsecs;
	}

	public void setUnixNsecs(long unixNsecs) {
		this.unixNsecs = unixNsecs;
	}

	public long getFlowSequence() {
		return flowSequence;
	}

	public void setFlowSequence(long flowSequence) {
		this.flowSequence = flowSequence;
	}

	public int getEngineType() {
		return engineType;
	}

	public void setEngineType(int engineType) {
		this.engineType = engineType;
	}

	public int getEngineId() {
		return engineId;
	}

	public void setEngineId(int engineId) {
		this.engineId = engineId;
	}

	public int getSamplingMode() {
		return samplingMode;
	}

	public void setSamplingMode(int samplingMode) {
		this.samplingMode = samplingMode;
	}

	public int getSamplingInterval() {
		return samplingInterval;
	}

	public void setSamplingInterval(int samplingInterval) {
		this.samplingInterval = samplingInterval;
	}

	public Map<String, Object> toMap() {
		HashMap<String, Object> m = new HashMap<String, Object>();
		m.put("version", version);
		m.put("count", count);
		m.put("sys_uptime", sysUptime);
		m.put("unix_secs", unixSecs);
		m.put("unix_nsecs", unixNsecs);
		m.put("flow_seq", flowSequence);
		m.put("engine_type", engineType);
		m.put("engine_id", engineId);
		m.put("sampling_mode", samplingMode);
		m.put("sampling_interval", samplingInterval);
		return m;
	}

	@Override
	public String toString() {
		return "ver=" + version + ", count=" + count + ", sysuptime=" + sysUptime + ", unixsecs=" + unixSecs + ", unixnsecs="
				+ unixNsecs + ", seq=" + flowSequence + ", engine_type=" + engineType + ", engine_id=" + engineId
				+ ", sampling_mode=" + samplingMode + ", sampling_interval=" + samplingInterval;
	}

}

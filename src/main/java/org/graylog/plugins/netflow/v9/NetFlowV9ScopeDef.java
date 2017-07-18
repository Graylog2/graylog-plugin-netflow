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
 * @since 0.1.0
 * @author xeraph
 */
public class NetFlowV9ScopeDef {
	public static final int SYSTEM = 1;
	public static final int INTERFACE = 2;
	public static final int LINECARD = 3;
	public static final int NETFLOW_CACHE = 4;
	public static final int TEMPLATE = 5;

	private int type;
	private int length;

	public NetFlowV9ScopeDef(int type, int length) {
		this.type = type;
		this.length = length;
	}

	public int getType() {
		return type;
	}

	public void setType(int type) {
		this.type = type;
	}

	public int getLength() {
		return length;
	}

	public void setLength(int length) {
		this.length = length;
	}
}

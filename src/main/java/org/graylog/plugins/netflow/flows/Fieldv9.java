/**
 * Copyright (C) 2012, 2013, 2014 wasted.io Ltd <really@wasted.io>
 * Copyright (C) 2015-2017 Graylog, Inc. (hello@graylog.org)
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

package org.graylog.plugins.netflow.flows;

import io.netty.buffer.ByteBuf;
import java.net.InetAddress;

import static org.graylog.plugins.netflow.utils.ByteBufUtils.getUnsignedInteger;
import static org.graylog.plugins.netflow.utils.ByteBufUtils.getInetAddress;

public class Fieldv9 {
	private int fieldType;
	private int fieldLength;
	private int fieldDataType=0; 

	private long numericField;
	private InetAddress address;
	private String string = "NONE";

	public Fieldv9(int fieldType, int fieldLength, int fieldDataType){
		this.fieldType = fieldType;
		this.fieldLength = fieldLength;
		this.fieldDataType = fieldDataType;
	}
	
	public Fieldv9(int fieldType, int fieldLength, int fieldDataType, InetAddress addy){
		this.fieldType = fieldType;
		this.fieldLength = fieldLength;
		this.fieldDataType = fieldDataType;
		this.address = addy;
	}
	
	public Fieldv9(int fieldType, int fieldLength, int fieldDataType, long num){
		this.fieldType = fieldType;
		this.fieldLength = fieldLength;
		this.fieldDataType = fieldDataType;
		this.numericField = num;
	}
	
	public int getFieldType() {
		return this.fieldType;
	}

	public int getFieldLen() {
		return this.fieldLength;
	}
	
	public Fieldv9 getNewFieldWithValue(ByteBuf subBuf, int i) {
		if(this.fieldDataType == 0) {
			return new Fieldv9(fieldType, fieldLength, fieldDataType, getUnsignedInteger(subBuf, i, fieldLength));
		} else if(this.fieldDataType == 1) {
			return new Fieldv9(fieldType, fieldLength, fieldDataType, getInetAddress(subBuf, i, fieldLength));
		} else {
			return new Fieldv9(fieldType,fieldLength,fieldDataType);
		}
	}

	public Object getValue() {
		if (fieldDataType == 0) {
			return numericField;
		} else if(fieldDataType == 1) {
			return address;
		} else {
			return string;
		}
	}

	public String getValueAsString() {
		return getValue().toString();
	}
	
}

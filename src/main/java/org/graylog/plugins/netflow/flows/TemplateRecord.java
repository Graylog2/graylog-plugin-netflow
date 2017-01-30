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

import java.util.List;

import javax.annotation.Nullable;

import org.graylog2.plugin.Message;

public class TemplateRecord extends Record{
	private int templateID;
	private int fieldCount; 
	private List<Fieldv9> fields;
	
	public TemplateRecord(int templateID, int fieldCount, List<Fieldv9> fields) {
		this.templateID=templateID;
		this.fieldCount = fieldCount;
		this.fields = fields;
	}

	public int getId(){
		return this.templateID;		
	}

	@Override
	@Nullable
	public Message toMessage() {
		return null;
	}

	@Override
	public String toMessageString() {
		return messageType();
	}

	@Override
	public String messageType() {
		return "TemplateRecord";
	}

	public int getFieldCount() {
		return fieldCount;
	}

	public List<Fieldv9> getFields() {
		return this.fields;
	}

}

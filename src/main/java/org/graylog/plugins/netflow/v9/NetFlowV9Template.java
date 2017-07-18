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
public class NetFlowV9Template {
	private int templateId;
	private int fieldCount;
	private List<NetFlowV9FieldDef> definitions = new ArrayList<NetFlowV9FieldDef>();

	public int getTemplateId() {
		return templateId;
	}

	public void setTemplateId(int templateId) {
		this.templateId = templateId;
	}

	public int getFieldCount() {
		return fieldCount;
	}

	public void setFieldCount(int fieldCount) {
		this.fieldCount = fieldCount;
	}

	public List<NetFlowV9FieldDef> getDefinitions() {
		return definitions;
	}

	public void setDefinitions(List<NetFlowV9FieldDef> definitions) {
		this.definitions = definitions;
	}

	@Override
	public String toString() {
		return "template " + templateId + ", field count=" + fieldCount + ", definitions=" + definitions;
	}

}

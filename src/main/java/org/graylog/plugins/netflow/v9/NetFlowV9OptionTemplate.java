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
public class NetFlowV9OptionTemplate {
	private int templateId;

	private List<NetFlowV9ScopeDef> scopeDefs = new ArrayList<NetFlowV9ScopeDef>();
	private List<NetFlowV9FieldDef> optionDefs = new ArrayList<NetFlowV9FieldDef>();

	public int getTemplateId() {
		return templateId;
	}

	public void setTemplateId(int templateId) {
		this.templateId = templateId;
	}

	public List<NetFlowV9ScopeDef> getScopeDefs() {
		return scopeDefs;
	}

	public void setScopeDefs(List<NetFlowV9ScopeDef> scopeDefs) {
		this.scopeDefs = scopeDefs;
	}

	public List<NetFlowV9FieldDef> getOptionDefs() {
		return optionDefs;
	}

	public void setOptionDefs(List<NetFlowV9FieldDef> optionDefs) {
		this.optionDefs = optionDefs;
	}
}

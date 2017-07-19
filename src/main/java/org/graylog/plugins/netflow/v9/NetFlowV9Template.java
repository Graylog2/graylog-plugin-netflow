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

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;

import java.util.List;

@AutoValue
public abstract class NetFlowV9Template {
    public abstract int templateId();

    public abstract int fieldCount();

    public abstract ImmutableList<NetFlowV9FieldDef> definitions();

    public static NetFlowV9Template create(int templateId,
                                           int fieldCount,
                                           List<NetFlowV9FieldDef> definitions) {
        return new AutoValue_NetFlowV9Template(templateId, fieldCount, ImmutableList.copyOf(definitions));
    }

}

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

@AutoValue
public abstract class NetFlowV9FieldType {
    public abstract int id();

    public abstract ValueType valueType();

    public abstract String name();

    public static NetFlowV9FieldType create(int id, ValueType valueType, String name) {
        return new AutoValue_NetFlowV9FieldType(id, valueType, name);
    }

    public enum ValueType {
        UINT8(1), INT8(1), UINT16(2), INT16(2), UINT32(4), INT32(4), INT64(8), IPV4(4), IPV6(16), MAC(6), STRING(0), VARINT(0);

        private final int defaultLength;

        ValueType(int defaultLength) {
            this.defaultLength = defaultLength;
        }

        public int getDefaultLength() {
            return defaultLength;
        }
    }
}

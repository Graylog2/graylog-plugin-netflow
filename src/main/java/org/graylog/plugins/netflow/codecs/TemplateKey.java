/*
 * Copyright 2017 Graylog Inc.
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
package org.graylog.plugins.netflow.codecs;

import com.google.common.base.MoreObjects;

import java.net.SocketAddress;
import java.util.Objects;

/**
 * The unique key for template flow ids, which is exporter source address and its obversation id (source ID)
 */
public class TemplateKey {
    private final SocketAddress remoteAddress;
    private final long sourceId;
    private final int templateId;

    public TemplateKey(SocketAddress remoteAddress, long sourceId, int templateId) {
        this.remoteAddress = remoteAddress;
        this.sourceId = sourceId;
        this.templateId = templateId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TemplateKey that = (TemplateKey) o;
        return sourceId == that.sourceId &&
                templateId == that.templateId &&
                Objects.equals(remoteAddress, that.remoteAddress);
    }

    public SocketAddress getRemoteAddress() {
        return remoteAddress;
    }

    public long getSourceId() {
        return sourceId;
    }

    public int getTemplateId() {
        return templateId;
    }

    @Override
    public int hashCode() {
        return Objects.hash(remoteAddress, sourceId, templateId);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("remoteAddress", remoteAddress)
                .add("sourceId", sourceId)
                .add("templateId", templateId)
                .toString();
    }
}

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

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheBuilderSpec;

import javax.annotation.Nullable;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static java.util.Objects.requireNonNull;

// TODO: Persist templates to file over restarts
public class NetFlowV9TemplateCache {
    private final Cache<Integer, NetFlowV9Template> cache;

    public NetFlowV9TemplateCache(long maximumSize,
                                  Duration expireDuration) {
        this(CacheBuilder.newBuilder()
                .maximumSize(maximumSize)
                .expireAfterAccess(expireDuration.toMillis(), TimeUnit.MILLISECONDS)
                .build());
    }

    public NetFlowV9TemplateCache(CacheBuilderSpec spec) {
        this(CacheBuilder.from(spec).build());
    }

    private NetFlowV9TemplateCache(Cache<Integer, NetFlowV9Template> cache) {
        this.cache = requireNonNull(cache, "cache");
    }

    public void put(int id, NetFlowV9Template template) {
        cache.put(id, template);
    }

    @Nullable
    public NetFlowV9Template get(int id) {
        return cache.getIfPresent(id);
    }
}

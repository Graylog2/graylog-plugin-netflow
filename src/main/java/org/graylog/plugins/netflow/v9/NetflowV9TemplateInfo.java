package org.graylog.plugins.netflow.v9;

import com.google.auto.value.AutoValue;

import java.util.List;

@AutoValue
public abstract class NetflowV9TemplateInfo {

    public abstract NetFlowV9Header header();

    public abstract List<NetFlowV9Template> allTemplates();

    public abstract NetFlowV9OptionTemplate optionTemplate();

    public abstract List<Integer> usedTemplatesIds();

    public static NetflowV9TemplateInfo create(NetFlowV9Header header, List<NetFlowV9Template> allTemplates, NetFlowV9OptionTemplate optionTemplate, List<Integer> usedTemplateIds) {
        return new AutoValue_NetflowV9TemplateInfo(header, allTemplates, optionTemplate, usedTemplateIds);
    }
}

package org.graylog.plugins.netflow.flows;

import java.util.List;

import javax.annotation.Nullable;

import org.graylog2.plugin.Message;

import com.beust.jcommander.internal.Lists;

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
		// N/A
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
		return Lists.newLinkedList(fields);
	}

}

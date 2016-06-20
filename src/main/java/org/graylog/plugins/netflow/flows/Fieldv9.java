package org.graylog.plugins.netflow.flows;

import io.netty.buffer.ByteBuf;
import com.google.common.net.InetAddresses;
import java.net.InetAddress;

import static org.graylog.plugins.netflow.utils.ByteBufUtils.getUnsignedInteger;
import static org.graylog.plugins.netflow.utils.ByteBufUtils.getInetAddress;

public class Fieldv9 {
	private int fieldType;
	private int fieldLength;
	private int fieldDataType=0; 
	//0 numeric, 1 Inet, 2 String
	private long numericField;
	private InetAddress address;
	private String string = "NONE";
	//0 unsigned int
	//1 Byte--offseit??
	//2 Short?
	//3 Medium?
	//4 Int or IPv4
	//8 long
	//16 IPv6
	
	
	
	
	public Fieldv9(int fieldType, int fieldLength) {
		this.fieldType = fieldType;
		this.fieldLength = fieldLength;
	}
	
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
	
	public int getFieldType(){return this.fieldType;}
	public int getFieldLen(){ return this.fieldLength;}
	//private void setFieldValue(Number val){ this.fieldValue = val;}
	
	public Fieldv9 getNewFieldWithValue(ByteBuf subBuf, int i) {
		// Tests for type of flow and returns a "deep copy" of v9 field
		if(this.fieldDataType == 0) 
			return new Fieldv9(fieldType,fieldLength,fieldDataType, getUnsignedInteger(subBuf,i, fieldLength));
		else if(this.fieldDataType == 1) 
			return new Fieldv9(fieldType,fieldLength,fieldDataType, 
					getInetAddress(subBuf,i, fieldLength));
		else return new Fieldv9(fieldType,fieldLength,fieldDataType);
	}


	public Object getValue() {
		// TODO Throw exception?
		if(fieldDataType == 0) return numericField;
		else if(fieldDataType == 1) return address; 
		else return string;
	}

	public String getValueAsString() {
		return getValue().toString();
	}
	
}

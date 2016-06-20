package org.graylog.plugins.netflow.flows;

import com.google.common.base.MoreObjects;

import com.google.common.collect.Lists;
import io.netty.buffer.ByteBuf;

import org.graylog.plugins.netflow.codecs.NetFlowCodec;
import org.graylog.plugins.netflow.codecs.TemplateStore;
import org.graylog.plugins.netflow.utils.UUIDs;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

import static org.graylog.plugins.netflow.utils.ByteBufUtils.getUnsignedInteger;
//* *-------*---------------*------------------------------------------------------*
//* | Bytes | Contents      | Description                                          |
//* *-------*---------------*------------------------------------------------------*
//* | 0-1   | version       | The version of NetFlow records exported 005          |
//* *-------*---------------*------------------------------------------------------*
//* | 2-3   | count         | Number of flows exported in this packet (1-30)       |
//* *-------*---------------*------------------------------------------------------*
//* | 4-7   | SysUptime     | Current time in milli since the export device booted |
//* *-------*---------------*------------------------------------------------------*
//* | 8-11  | unix_secs     | Current count of seconds since 0000 UTC 1970         |
//* *-------*---------------*------------------------------------------------------*
//* | 12-15 | Package Sequen|Incremental sequence counter of all
//							 export packets sent by this export device; 
//							 this value is cumulative, and it can be used 
//							 to identify whether any export packets have been miss 
//							 |
//* *-------*---------------*------------------------------------------------------*
//* | 16-19 | Source ID      | Unique source id
//* *-------*---------------*------------------------------------------------------*

//https://www.ietf.org/rfc/rfc3954.txt
//0                   1                   2                   3
//0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|       FlowSet ID = 0          |          Length               |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|      Template ID 256          |         Field Count           |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|        Field Type 1           |         Field Length 1        |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|        Field Type 2           |         Field Length 2        |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|             ...               |              ...              |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|        Field Type N           |         Field Length N        |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|      Template ID 257          |         Field Count           |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|        Field Type 1           |         Field Length 1        |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|        Field Type 2           |         Field Length 2        |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|             ...               |              ...              |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|        Field Type M           |         Field Length M        |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|             ...               |              ...              |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|        Template ID K          |         Field Count           |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|             ...               |              ...              |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+



public class NetFlowV9Packet implements NetFlowPacket {
    private static final Logger LOG = LoggerFactory.getLogger(NetFlowV9Packet.class);
    private final UUID id;
    private final InetSocketAddress sender;
    private final int length;
    private final long uptime;
    private final DateTime timestamp;
    private final List<NetFlow> flows;
    private long packetSequence;
    private int sessionId;

    public NetFlowV9Packet(UUID id,InetSocketAddress sender,
                           int length,long uptime,
                           DateTime timestamp,List<NetFlow> flows,
                           long packetSequence, 
                           int sessionId) {

        this.id = id;
        this.sender = sender;
        this.length = length;
        this.uptime = uptime;
        this.timestamp = timestamp;
        this.flows = flows;
        this.packetSequence = packetSequence;
        this.sessionId = sessionId;
    }

	
	
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public Collection getFlows() {
		return flows; 
		}
	
	@Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("id", id)
                .add("sender", sender)
                .add("length", length)
                .add("uptime", uptime)
                .add("timestamp", timestamp)
                .add("flows", flows)
                .add("packetSequence", packetSequence)
                .add("engineId", sessionId)
                .toString();
    }
	
	public static NetFlowV9Packet parse(InetSocketAddress sender, ByteBuf buf, TemplateStore v9templates) throws InvalidFlowVersionException, CorruptFlowPacketException {

        final int version = (int) getUnsignedInteger(buf, 0, 2);
        if (version != 9) {
            throw new InvalidFlowVersionException(version);
        }

        int count = (int) getUnsignedInteger(buf, 2, 2);
        final long uptime = getUnsignedInteger(buf, 4, 4);
        final DateTime timestamp = new DateTime(getUnsignedInteger(buf, 8, 4) * 1000, DateTimeZone.UTC);
        final UUID id = UUIDs.startOf(timestamp.getMillis());
        final long packetSequence = getUnsignedInteger(buf, 12, 4);
        final int sessionId = (int) getUnsignedInteger(buf, 16, 4);
        final List<NetFlow> flows = Lists.newLinkedList();
        int i = 20; //should start on 20th byte
        int numFlow = 0;
        while(numFlow < (count) && i < buf.capacity()){        	
        	int recordType = (int) getUnsignedInteger(buf, i, 2); 
        	int recordLength = (int) getUnsignedInteger(buf, i+2, 2);
        	ByteBuf subBuf = buf.slice(i, recordLength);
        	Record record = null;
        	LOG.info("recordType "+Integer.toString(recordType) 
        			+"recordLength "+Integer.toString(recordLength));
        	if(isTemplateFlowSet(recordType))  
        		parseTemplateRecords(subBuf, v9templates);
        	else if(isOptionRecord(recordType)) {
        		record = parseOptionRecord(subBuf,v9templates);
        		}
        	else{ 
        		record = parseDataRecords(subBuf,v9templates, id, sender, timestamp);
        	}
            if(!isTemplateFlowSet(recordType) && !isOptionRecord(recordType) && record != null){        	
            	flows.add(record);
            	}
            i+=recordLength;
            numFlow+=1;
            LOG.info("Loop? numFlows = "+Integer.toString(numFlow)+" i = "+Integer.toString(i)+
            		" buf cap "+Integer.toString(buf.capacity())+" session id "+Integer.toString(sessionId)
            		+" flows list length "+Integer.toString(flows.size())
            		);
            
        }
        return new NetFlowV9Packet(
        		id, sender, buf.readableBytes(), uptime, 
        		timestamp, flows, packetSequence, sessionId);
    }

	@SuppressWarnings("unused")
	private void addRecordsToFlows(List<NetFlow> flows, List<Record> records) {
		//Iterates over records adding to flows
		for(Record record : records){
			flows.add(record);			
		}
	}

	private static Record parseDataRecords(ByteBuf subBuf,
			TemplateStore v9templates, UUID id, InetSocketAddress sender, DateTime ts) {
		int i = 0;
		int flowSetId = (int) getUnsignedInteger(subBuf, i, 2);
		i+=4;
		//Try can catch in case empty map
		TemplateRecord template = v9templates.getTemplate(flowSetId);
		LOG.info(" We requested "+Integer.toString(flowSetId));
		if(template == null) return null; //No template defined yet
		LOG.info(" WE HAVE GOTTEN PAST THE NO TEMPLATES!!!");
		int fieldCount = template.getFieldCount();
		List<Fieldv9> fields = template.getFields();
		Iterator<Fieldv9> fieldIter = fields.iterator();
		Fieldv9 field = null;
		List<Fieldv9> dataList = Lists.newLinkedList();
		for(int j = 0; j < fieldCount; j++){
			if(fieldIter.hasNext()){ 
				field = fieldIter.next();
				dataList.add(field.getNewFieldWithValue(subBuf, i));
				i+= field.getFieldLen();
			}
			 
			//else{ We have padding!}
			}
		    //The following line replaces the parse 
		    //functionality of the NetFlowV5 class
		    return new DataRecord(id, sender, ts, dataList, v9templates);
		}
		
		
	

	private static Record parseOptionRecord(ByteBuf subBuf,
			TemplateStore v9templates)  {
			//No need to track options at this time
		return null;
	}
	private static void parseTemplateRecords(ByteBuf subBuf, TemplateStore v9templates) {
		//This method adds templates to TemplatesStore 
		
		int i = 0;
		int templateID=0;
		int fieldCount=0;
		List<Fieldv9> fields = null;
		@SuppressWarnings("unused")
		int flowSetId = (int) getUnsignedInteger(subBuf, i, 2);
		int rLength = (int) getUnsignedInteger(subBuf, i+2, 2);
		i+=4;
		while(i <= (rLength-1)){
			templateID = (int) getUnsignedInteger(subBuf, i, 2);
			fieldCount = (int) getUnsignedInteger(subBuf, i+2, 2);
			i += 4;
			fields = Lists.newLinkedList();
			for(int numFields = 0; numFields < fieldCount; numFields+=1){
				int fieldType = (int) getUnsignedInteger(subBuf, i, 2);
				int fieldLength = (int) getUnsignedInteger(subBuf, i+2, 2);
				i+=4;
				if(v9templates.isIP(fieldType)) fields.add(new Fieldv9(fieldType, fieldLength,1));
				else if(isParsable(fieldLength)) fields.add(new Fieldv9(fieldType, fieldLength,0));
				else fields.add(new Fieldv9(fieldType, fieldLength,2));
			}
			LOG.info("Template to add "+Integer.toString(templateID));
			v9templates.putIdToRecord(new TemplateRecord(templateID, fieldCount, fields));
		}
		LOG.info("Temp Store template map size is "+Integer.toString(v9templates.getTemplateMapSize()));
		
	}
	
	private static boolean isParsable(int x) {
		return (x==1 || x == 2 || x == 3 || x == 4 || x == 8);
	}



	private static boolean isOptionRecord(int recordType) {
		return recordType == 1;
	}
	private static boolean isTemplateFlowSet(int recordType) {
		return recordType == 0;
	}

	
	}


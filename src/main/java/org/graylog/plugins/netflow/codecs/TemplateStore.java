package org.graylog.plugins.netflow.codecs;

import java.util.HashMap;
import java.util.HashSet;

import org.graylog.plugins.netflow.flows.NetFlowV9Packet;
import org.graylog.plugins.netflow.flows.TemplateRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



public class TemplateStore {
	//Future work file IO to add more field types, ==> do IPFix
	private static final Logger LOG = LoggerFactory.getLogger(TemplateStore.class);{
	LOG.warn("Is singleton? FOOBAR!!!!");
	}
	
	
	private HashMap<Integer,TemplateRecord> idToRecord = new HashMap<Integer,TemplateRecord>();
	
	static private HashMap<Integer,String> idToString = new  HashMap<Integer,String>();
	{
		idToString.put(1,"IN_BYTES");
		idToString.put(2,"IN_PKTS");
		idToString.put(3,"FLOWS");
		idToString.put(4,"NF_F_PROTOCOL");
		idToString.put(4,"PROTOCOL");
		idToString.put(5,"SRC_TOS");
		idToString.put(6,"TCP_FLAGS");
		idToString.put(7,"NF_F_SRC_PORT");
		idToString.put(7,"L4_SRC_PORT");
		idToString.put(8,"NF_F_SRC_ADDR_IPV4");
		idToString.put(8,"IPV4_SRC_ADDR");
		idToString.put(9,"SRC_MASK");
		idToString.put(10,"NF_F_SRC_INTF_ID");
		idToString.put(10,"INPUT_SNMP");
		idToString.put(11,"NF_F_DST_PORT");
		idToString.put(11,"L4_DST_PORT");
		idToString.put(12,"NF_F_DST_ADDR_IPV4");
		idToString.put(12,"IPV4_DST_ADDR");
		idToString.put(13,"DST_MASK");
		idToString.put(14,"NF_F_DST_INTF_ID");
		idToString.put(14,"OUTPUT_SNMP");
		idToString.put(15,"IPV4_NEXT_HOP");
		idToString.put(16,"SRC_AS");
		idToString.put(17,"DST_AS");
		idToString.put(18,"BGP_IPV4_NEXT_HOP");
		idToString.put(19,"MUL_DST_PKTS");
		idToString.put(20,"MUL_DST_BYTES");
		idToString.put(21,"LAST_SWITCHED");
		idToString.put(22,"FIRST_SWITCHED");
		idToString.put(23,"OUT_BYTES");
		idToString.put(24,"OUT_PKTS");
		idToString.put(25,"MIN_PKT_LNGTH");
		idToString.put(26,"MAX_PKT_LNGTH");
		idToString.put(27,"NF_F_SRC_ADDR_IPV6");
		idToString.put(27,"IPV6_SRC_ADDR");
		idToString.put(28,"NF_F_DST_ADDR_IPV6");
		idToString.put(28,"IPV6_DST_ADDR");
		idToString.put(29,"IPV6_SRC_MASK");
		idToString.put(30,"IPV6_DST_MASK");
		idToString.put(31,"IPV6_FLOW_LABEL");
		idToString.put(32,"ICMP_TYPE");
		idToString.put(33,"MUL_IGMP_TYPE");
		idToString.put(34,"SAMPLING_INTERVAL");
		idToString.put(35,"SAMPLING_ALGORITHM");
		idToString.put(36,"FLOW_ACTIVE_TIMEOUT");
		idToString.put(37,"FLOW_INACTIVE_TIMEOUT");
		idToString.put(38,"ENGINE_TYPE");
		idToString.put(39,"ENGINE_ID");
		idToString.put(40,"TOTAL_BYTES_EXP");
		idToString.put(41,"TOTAL_PKTS_EXP");
		idToString.put(42,"TOTAL_FLOWS_EXP");
		idToString.put(43,"*Vendor Proprietary*");
		idToString.put(44,"IPV4_SRC_PREFIX");
		idToString.put(45,"IPV4_DST_PREFIX");
		idToString.put(46,"MPLS_TOP_LABEL_TYPE");
		idToString.put(47,"MPLS_TOP_LABEL_IP_ADDR");
		idToString.put(48,"FLOW_SAMPLER_ID");
		idToString.put(49,"FLOW_SAMPLER_MODE");
		idToString.put(50,"FLOW_SAMPLER_RANDOM_INTERVAL");
		idToString.put(51,"*Vendor Proprietary*");
		idToString.put(52,"MIN_TTL");
		idToString.put(53,"MAX_TTL");
		idToString.put(54,"IPV4_IDENT");
		idToString.put(55,"DST_TOS");
		idToString.put(56,"IN_SRC_MAC");
		idToString.put(57,"OUT_DST_MAC");
		idToString.put(58,"SRC_VLAN");
		idToString.put(59,"DST_VLAN");
		idToString.put(60,"IP_PROTOCOL_VERSION");
		idToString.put(61,"DIRECTION");
		idToString.put(62,"IPV6_NEXT_HOP");
		idToString.put(63,"BPG_IPV6_NEXT_HOP");
		idToString.put(64,"IPV6_OPTION_HEADERS");
		idToString.put(65,"*Vendor Proprietary*");
		idToString.put(66,"*Vendor Proprietary*");
		idToString.put(67,"*Vendor Proprietary*");
		idToString.put(68,"*Vendor Proprietary*");
		idToString.put(69,"*Vendor Proprietary*");
		idToString.put(70,"MPLS_LABEL_1");
		idToString.put(71,"MPLS_LABEL_2");
		idToString.put(72,"MPLS_LABEL_3");
		idToString.put(73,"MPLS_LABEL_4");
		idToString.put(74,"MPLS_LABEL_5");
		idToString.put(75,"MPLS_LABEL_6");
		idToString.put(76,"MPLS_LABEL_7");
		idToString.put(77,"MPLS_LABEL_8");
		idToString.put(78,"MPLS_LABEL_9");
		idToString.put(79,"MPLS_LABEL_10");
		idToString.put(80,"IN_DST_MAC");
		idToString.put(81,"OUT_SRC_MAC");
		idToString.put(82,"IF_NAME");
		idToString.put(83,"IF_DESC");
		idToString.put(84,"SAMPLER_NAME");
		idToString.put(85,"IN_ PERMANENT _BYTES");
		idToString.put(86,"IN_ PERMANENT _PKTS");
		idToString.put(87,"* Vendor Proprietary*");
		idToString.put(88,"FRAGMENT_OFFSET");
		idToString.put(89,"FORWARDING STATUS");
		idToString.put(90,"MPLS PAL RD");
		idToString.put(91,"MPLS PREFIX LEN");
		idToString.put(92,"SRC TRAFFIC INDEX");
		idToString.put(93,"DST TRAFFIC INDEX");
		idToString.put(94,"APPLICATION DESCRIPTION");
		idToString.put(95,"APPLICATION TAG");
		idToString.put(96,"APPLICATION NAME");
		idToString.put(98,"postipDiffServCodePoint");
		idToString.put(99,"replication factor");
		idToString.put(100,"DEPRECATED");
		idToString.put(102,"layer2packetSectionOffset");
		idToString.put(103,"layer2packetSectionSize");
		idToString.put(104,"layer2packetSectionData");
		idToString.put(148,"NF_F_CONN_ID");
		idToString.put(152,"NF_F_FLOW_CREATE_TIME_MSEC");
		idToString.put(176,"NF_F_ICMP_TYPE");
		idToString.put(177,"NF_F_ICMP_CODE");
		idToString.put(178,"NF_F_ICMP_TYPE_IPV6");
		idToString.put(179,"NF_F_ICMP_CODE_IPV6");
		idToString.put(225,"NF_F_XLATE_SRC_ADDR_IPV4");
		idToString.put(226,"NF_F_XLATE_DST_ADDR_IPV4");
		idToString.put(227,"NF_F_XLATE_SRC_PORT");
		idToString.put(228,"NF_F_XLATE_DST_PORT");
		idToString.put(231,"NF_F_FWD_FLOW_DELTA_BYTES");
		idToString.put(232,"NF_F_REV_FLOW_DELTA_BYTES");
		idToString.put(233,"NF_F_FW_EVENT");
		idToString.put(281,"NF_F_XLATE_SRC_ADDR_IPV6");
		idToString.put(282,"NF_F_XLATE_DST_ADDR_IPV6");
		idToString.put(323,"NF_F_EVENT_TIME_MSEC");
		idToString.put(33000,"NF_F_INGRESS_ACL_ID");
		idToString.put(33001,"NF_F_EGRESS_ACL_ID");
		idToString.put(33002,"NF_F_FW_EXT_EVENT");
		idToString.put(40000,"NF_F_USERNAME");
		idToString.put(40000,"NF_F_USERNAME_MAX");
	};
	
	static private HashSet<Integer> inetIds = new HashSet<Integer>();{
		//IPv4 fields
		inetIds.add(18);
		inetIds.add(15);
		inetIds.add(12);
		inetIds.add(8);
		inetIds.add(44);
		inetIds.add(45);
		//IPv6 Fields
		inetIds.add(27);
		inetIds.add(28);
		inetIds.add(62);
		inetIds.add(63);
		inetIds.add(281);
		inetIds.add(282);
		}
	
	static private HashMap<String, Integer> stringToId = new  HashMap<String, Integer>();
	{
		stringToId.put("IN_BYTES",1);
		stringToId.put("IN_PKTS",2);
		stringToId.put("FLOWS",3);
		stringToId.put("NF_F_PROTOCOL",4);
		stringToId.put("PROTOCOL",4);
		stringToId.put("SRC_TOS",5);
		stringToId.put("TCP_FLAGS",6);
		stringToId.put("NF_F_SRC_PORT",7);
		stringToId.put("L4_SRC_PORT",7);
		//stringToId.put("NF_F_SRC_ADDR_IPV4",8);
		stringToId.put("IPV4_SRC_ADDR",8);
		stringToId.put("SRC_MASK",9);
		stringToId.put("NF_F_SRC_INTF_ID",10);
		stringToId.put("INPUT_SNMP",10);
		stringToId.put("NF_F_DST_PORT",11);
		stringToId.put("L4_DST_PORT",11);
		//stringToId.put("NF_F_DST_ADDR_IPV4",12);
		stringToId.put("IPV4_DST_ADDR",12);
		stringToId.put("DST_MASK",13);
		stringToId.put("NF_F_DST_INTF_ID",14);
		stringToId.put("OUTPUT_SNMP",14);
		stringToId.put("IPV4_NEXT_HOP",15);
		stringToId.put("SRC_AS",16);
		stringToId.put("DST_AS",17);
		stringToId.put("BGP_IPV4_NEXT_HOP",18);
		stringToId.put("MUL_DST_PKTS",19);
		stringToId.put("MUL_DST_BYTES",20);
		stringToId.put("LAST_SWITCHED",21);
		stringToId.put("FIRST_SWITCHED",22);
		stringToId.put("OUT_BYTES",23);
		stringToId.put("OUT_PKTS",24);
		stringToId.put("MIN_PKT_LNGTH",25);
		stringToId.put("MAX_PKT_LNGTH",26);
//		stringToId.put("NF_F_SRC_ADDR_IPV6",27);
		stringToId.put("IPV6_SRC_ADDR",27);
		stringToId.put("NF_F_DST_ADDR_IPV6",28);
		stringToId.put("IPV6_DST_ADDR",28);
		stringToId.put("IPV6_SRC_MASK",29);
		stringToId.put("IPV6_DST_MASK",30);
		stringToId.put("IPV6_FLOW_LABEL",31);
		stringToId.put("ICMP_TYPE",32);
		stringToId.put("MUL_IGMP_TYPE",33);
		stringToId.put("SAMPLING_INTERVAL",34);
		stringToId.put("SAMPLING_ALGORITHM",35);
		stringToId.put("FLOW_ACTIVE_TIMEOUT",36);
		stringToId.put("FLOW_INACTIVE_TIMEOUT",37);
		stringToId.put("ENGINE_TYPE",38);
		stringToId.put("ENGINE_ID",39);
		stringToId.put("TOTAL_BYTES_EXP",40);
		stringToId.put("TOTAL_PKTS_EXP",41);
		stringToId.put("TOTAL_FLOWS_EXP",42);
		stringToId.put("*Vendor Proprietary*",43);
		stringToId.put("IPV4_SRC_PREFIX",44);
		stringToId.put("IPV4_DST_PREFIX",45);
		stringToId.put("MPLS_TOP_LABEL_TYPE",46);
		stringToId.put("MPLS_TOP_LABEL_IP_ADDR",47);
		stringToId.put("FLOW_SAMPLER_ID",48);
		stringToId.put("FLOW_SAMPLER_MODE",49);
		stringToId.put("FLOW_SAMPLER_RANDOM_INTERVAL",50);
		stringToId.put("*Vendor Proprietary*",51);
		stringToId.put("MIN_TTL",52);
		stringToId.put("MAX_TTL",53);
		stringToId.put("IPV4_IDENT",54);
		stringToId.put("DST_TOS",55);
		stringToId.put("IN_SRC_MAC",56);
		stringToId.put("OUT_DST_MAC",57);
		stringToId.put("SRC_VLAN",58);
		stringToId.put("DST_VLAN",59);
		stringToId.put("IP_PROTOCOL_VERSION",60);
		stringToId.put("DIRECTION",61);
		stringToId.put("IPV6_NEXT_HOP",62);
		stringToId.put("BPG_IPV6_NEXT_HOP",63);
		stringToId.put("IPV6_OPTION_HEADERS",64);
		stringToId.put("*Vendor Proprietary*",65);
		stringToId.put("*Vendor Proprietary*",66);
		stringToId.put("*Vendor Proprietary*",67);
		stringToId.put("*Vendor Proprietary*",68);
		stringToId.put("*Vendor Proprietary*",69);
		stringToId.put("MPLS_LABEL_1",70);
		stringToId.put("MPLS_LABEL_2",71);
		stringToId.put("MPLS_LABEL_3",72);
		stringToId.put("MPLS_LABEL_4",73);
		stringToId.put("MPLS_LABEL_5",74);
		stringToId.put("MPLS_LABEL_6",75);
		stringToId.put("MPLS_LABEL_7",76);
		stringToId.put("MPLS_LABEL_8",77);
		stringToId.put("MPLS_LABEL_9",78);
		stringToId.put("MPLS_LABEL_10",79);
		stringToId.put("IN_DST_MAC",80);
		stringToId.put("OUT_SRC_MAC",81);
		stringToId.put("IF_NAME",82);
		stringToId.put("IF_DESC",83);
		stringToId.put("SAMPLER_NAME",84);
		stringToId.put("IN_ PERMANENT _BYTES",85);
		stringToId.put("IN_ PERMANENT _PKTS",86);
		stringToId.put("* Vendor Proprietary*",87);
		stringToId.put("FRAGMENT_OFFSET",88);
		stringToId.put("FORWARDING STATUS",89);
		stringToId.put("MPLS PAL RD",90);
		stringToId.put("MPLS PREFIX LEN",91);
		stringToId.put("SRC TRAFFIC INDEX",92);
		stringToId.put("DST TRAFFIC INDEX",93);
		stringToId.put("APPLICATION DESCRIPTION",94);
		stringToId.put("APPLICATION TAG",95);
		stringToId.put("APPLICATION NAME",96);
		stringToId.put("postipDiffServCodePoint",98);
		stringToId.put("replication factor",99);
		stringToId.put("DEPRECATED",100);
		stringToId.put("layer2packetSectionOffset",102);
		stringToId.put("layer2packetSectionSize",103);
		stringToId.put("layer2packetSectionData",104);
		stringToId.put("NF_F_CONN_ID",148);
		stringToId.put("NF_F_FLOW_CREATE_TIME_MSEC",152);
		stringToId.put("NF_F_ICMP_TYPE",176);
		stringToId.put("NF_F_ICMP_CODE",177);
		stringToId.put("NF_F_ICMP_TYPE_IPV6",178);
		stringToId.put("NF_F_ICMP_CODE_IPV6",179);
		stringToId.put("NF_F_XLATE_SRC_ADDR_IPV4",225);
		stringToId.put("NF_F_XLATE_DST_ADDR_IPV4",226);
		stringToId.put("NF_F_XLATE_SRC_PORT",227);
		stringToId.put("NF_F_XLATE_DST_PORT",228);
		stringToId.put("NF_F_FWD_FLOW_DELTA_BYTES",231);
		stringToId.put("NF_F_REV_FLOW_DELTA_BYTES",232);
		stringToId.put("NF_F_FW_EVENT",233);
		stringToId.put("NF_F_XLATE_SRC_ADDR_IPV6",281);
		stringToId.put("NF_F_XLATE_DST_ADDR_IPV6",282);
		stringToId.put("NF_F_EVENT_TIME_MSEC",323);
		stringToId.put("NF_F_INGRESS_ACL_ID",33000);
		stringToId.put("NF_F_EGRESS_ACL_ID",33001);
		stringToId.put("NF_F_FW_EXT_EVENT",33002);
		stringToId.put("NF_F_USERNAME",40000);
		stringToId.put("NF_F_USERNAME_MAX",40000);
	}
	
	static private HashMap<Integer, Integer> idToLength = new  HashMap<Integer, Integer>();
	{
		idToLength.put(1,4 );//N (default is 4));
		idToLength.put(2,4 );//N (default is 4));
		idToLength.put(3,4); //N
		idToLength.put(4,1);
		idToLength.put(4,1);
		idToLength.put(5,1);
		idToLength.put(6,1);
		idToLength.put(7,2);
		idToLength.put(7,2);
		idToLength.put(8,4);
		idToLength.put(8,4);
		idToLength.put(9,1);
		idToLength.put(10,2);
		idToLength.put(10,4); //N
		idToLength.put(11,2);
		idToLength.put(11,2);
		idToLength.put(12,4);
		idToLength.put(12,4);
		idToLength.put(13,1);
		idToLength.put(14,2);
		idToLength.put(14,4); //N
		idToLength.put(15,4);
		idToLength.put(16,2); //(default is 2));
		idToLength.put(17,2); //(default is 2));
		idToLength.put(18,4);
		idToLength.put(19,4);//N (default is 4));
		idToLength.put(20,4);//N (default is 4));
		idToLength.put(21,4);
		idToLength.put(22,4);
		idToLength.put(23,4);//N (default is 4));
		idToLength.put(24,4);//N (default is 4));
		idToLength.put(25,2);
		idToLength.put(26,2);
		idToLength.put(27,16);
		idToLength.put(27,16);
		idToLength.put(28,16);
		idToLength.put(28,16);
		idToLength.put(29,1);
		idToLength.put(30,1);
		idToLength.put(31,3);
		idToLength.put(32,2);
		idToLength.put(33,1);
		idToLength.put(34,4);
		idToLength.put(35,1);
		idToLength.put(36,2);
		idToLength.put(37,2);
		idToLength.put(38,1);
		idToLength.put(39,1);
		idToLength.put(40,4);//N (default is 4));
		idToLength.put(41,4);//N (default is 4));
		idToLength.put(42,4);//N (default is 4));
		idToLength.put(44,4);
		idToLength.put(45,4);
		idToLength.put(46,1);
		idToLength.put(47,4);
		idToLength.put(48,1);
		idToLength.put(49,1);
		idToLength.put(50,4);
		idToLength.put(52,1);
		idToLength.put(53,1);
		idToLength.put(54,2);
		idToLength.put(55,1);
		idToLength.put(56,6);
		idToLength.put(57,6);
		idToLength.put(58,2);
		idToLength.put(59,2);
		idToLength.put(60,1);
		idToLength.put(61,1);
		idToLength.put(62,16);
		idToLength.put(63,16);
		idToLength.put(64,4);
		idToLength.put(70,3);
		idToLength.put(71,3);
		idToLength.put(72,3);
		idToLength.put(73,3);
		idToLength.put(74,3);
		idToLength.put(75,3);
		idToLength.put(76,3);
		idToLength.put(77,3);
		idToLength.put(78,3);
		idToLength.put(79,3);
		idToLength.put(80,6);
		idToLength.put(81,6);
		idToLength.put(82,-1); //N
		idToLength.put(83,-1); //N (default specified in template));
		idToLength.put(84,-1); //N (default specified in template));
		idToLength.put(85,-1); //N (default is 4));
		idToLength.put(86,-1); //N (default is 4));
		idToLength.put(88,2);
		idToLength.put(89,1);
		idToLength.put(90,-1 ); //(array));
		idToLength.put(91,1);
		idToLength.put(92,4);
		idToLength.put(93,4);
		idToLength.put(94,-1); //N
		idToLength.put(95,-1); //1+N;
		idToLength.put(96,-1);//N);
		idToLength.put(98,1);
		idToLength.put(99,4);
		idToLength.put(100,-1);
		idToLength.put(102,-1);
		idToLength.put(103,-1);
		idToLength.put(104,-1);
		idToLength.put(148,4);
		idToLength.put(152,8);
		idToLength.put(176,1);
		idToLength.put(177,1);
		idToLength.put(178,1);
		idToLength.put(179,1);
		idToLength.put(225,4);
		idToLength.put(226,4);
		idToLength.put(227,2);
		idToLength.put(228,2);
		idToLength.put(231,4);
		idToLength.put(232,4);
		idToLength.put(233,1);
		idToLength.put(281,16);
		idToLength.put(282,16);
		idToLength.put(323,8);
		idToLength.put(33000,12);
		idToLength.put(33001,12);
		idToLength.put(33002,2);
		idToLength.put(40000,20);
		idToLength.put(40000,65);

	}
	
	
	public void putIdToRecord(TemplateRecord templateRecord) {
		idToRecord.put( templateRecord.getId(), templateRecord);		
	}


	public TemplateRecord getTemplate(int flowSetId) {
		//Null if empty
		return idToRecord.get(flowSetId);
	}


	public boolean isIP(int id){return inetIds.contains(id);}
	
	public String getString(int fieldType) {
		//Null if empty
		return idToString.get(fieldType);
	}


	public String getStringOrElse(int fieldType, String string) {
		String ans = idToString.get(fieldType);
		if(ans == null) return string;
		else return ans;
	}


	public int getTemplateMapSize() {
		// TODO Auto-generated method stub
		return idToRecord.size();
	}

}

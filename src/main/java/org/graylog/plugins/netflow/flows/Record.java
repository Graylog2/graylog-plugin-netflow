package org.graylog.plugins.netflow.flows;

public abstract class Record implements NetFlow {
	//A Record class that Represents a NetflowV9 flowSet
	public abstract String messageType();
}



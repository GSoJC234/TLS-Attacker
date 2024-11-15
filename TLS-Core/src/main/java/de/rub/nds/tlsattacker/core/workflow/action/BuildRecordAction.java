/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import java.util.List;

public class BuildRecordAction extends TlsAction {

    private List<Record> record_container = null;

    private List<ProtocolMessageType> record_type_container = null;
    private List<ProtocolVersion> version_container = null;
    private List<Boolean> length_container = null;
    private List<ProtocolMessage> message_container = null;

    public BuildRecordAction(List<Record> record_container) {
        this.record_container = record_container;
    }

    public void setProtocolMessageType(List<ProtocolMessageType> record_type_container){
        this.record_type_container = record_type_container;
    }

    public void setProtocolVersion(List<ProtocolVersion> version_container){
        this.version_container = version_container;
    }

    public void setLength(List<Boolean> length_container){
        this.length_container = length_container;
    }

    public void setProtocolMessage(List<ProtocolMessage> message_container){
        this.message_container = message_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        Record record = new Record();

        record.setContentMessageType(record_type_container.get(0));
        record.setProtocolVersion((version_container.get(0)).getValue());
        if(length_container.get(0)){
            record.setLength(message_container.get(0).getCompleteResultingMessage().getValue().length);
        }
        record.setCleanProtocolMessageBytes(message_container.get(0).getCompleteResultingMessage());

        record_container.add(record);
    }

    @Override
    public void reset() {}

    @Override
    public boolean executedAsPlanned() {
        return true;
    }
}

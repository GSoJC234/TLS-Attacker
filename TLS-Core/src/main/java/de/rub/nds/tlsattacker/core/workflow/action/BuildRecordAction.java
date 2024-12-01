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
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.serializer.RecordSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;

@XmlRootElement(name = "BuildRecordAction")
public class BuildRecordAction extends TlsAction {

    @XmlTransient private List<Record> record_container = null;

    @XmlTransient private List<ProtocolMessageType> record_type_container = null;
    @XmlTransient private List<ProtocolVersion> version_container = null;
    @XmlTransient private List<Boolean> length_container = null;
    @XmlTransient private List<ProtocolMessage> message_container = null;

    public BuildRecordAction() {}

    public BuildRecordAction(List<Record> record_container) {
        this.record_container = record_container;
    }

    public void setProtocolMessageType(List<ProtocolMessageType> record_type_container) {
        this.record_type_container = record_type_container;
    }

    public void setProtocolVersion(List<ProtocolVersion> version_container) {
        this.version_container = version_container;
    }

    public void setLength(List<Boolean> length_container) {
        this.length_container = length_container;
    }

    public void setProtocolMessage(List<ProtocolMessage> message_container) {
        this.message_container = message_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        Record record = new Record();
        record.setShouldPrepare(false);
        record.setContentType(record_type_container.get(0).getValue());
        record.setProtocolVersion((version_container.get(0)).getValue());
        ProtocolMessage message = message_container.get(0);
        if (message instanceof HandshakeMessage) {
            record.setProtocolMessageBytes(message.getCompleteResultingMessage());
            record.setLength(record.getProtocolMessageBytes().getValue().length);
        }

        if (!length_container.get(0)) {
            throw new ActionExecutionException("Unsupported message length modification");
        }

        RecordSerializer serializer = new RecordSerializer(record);
        record.setCompleteRecordBytes(serializer.serialize());

        record_container.add(record);
        setExecuted(true);
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    @Override
    public boolean executedAsPlanned() {
        return true;
    }
}

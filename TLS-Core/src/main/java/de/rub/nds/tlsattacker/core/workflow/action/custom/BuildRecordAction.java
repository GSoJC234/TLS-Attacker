/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.serializer.RecordSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;

@XmlRootElement(name = "BuildRecordAction")
public class BuildRecordAction extends ConnectionBoundAction {

    @XmlTransient private List<Record> record_container = null;

    @XmlTransient private List<ProtocolMessageType> record_type_container = null;
    @XmlTransient private List<ProtocolVersion> version_container = null;
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

    public void setProtocolMessage(List<ProtocolMessage> message_container) {
        this.message_container = message_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext context = state.getTlsContext(getConnectionAlias());

        Record record = new Record();
        record.setShouldPrepare(false);
        record.setContentType(record_type_container.get(0).getValue());
        record.setContentMessageType(record_type_container.get(0));
        record.setProtocolVersion((version_container.get(0)).getValue());

        ProtocolMessage message = message_container.get(0);
        if (message instanceof HandshakeMessage) {
            HandshakeMessage handshakeMessage = (HandshakeMessage) message;

            context.setTalkingConnectionEndType(
                    context.getConnection().getLocalConnectionEndType());
            // HandshakeMessageHandler handler =
            //        handshakeMessage.getHandler(state.getTlsContext(getConnectionAlias()));
            // handler.adjustContext(handshakeMessage);
            // if (!(handshakeMessage instanceof FinishedMessage)) {
            //    // We do not consider after application data
            //    // For processing application data, this code should be revised
            //    handler.adjustContextAfterSerialize(handshakeMessage);
            // }

            // message.setAdjustContext(false);

        }
        record.setProtocolMessageBytes(message.getCompleteResultingMessage());
        record.setCleanProtocolMessageBytes(message.getCompleteResultingMessage());
        record.setLength(record.getProtocolMessageBytes().getValue().length);

        RecordSerializer serializer = new RecordSerializer(record);
        record.setCompleteRecordBytes(serializer.serialize());

        record_container.add(record);
        System.out.println("BuildRecord: " + message);
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

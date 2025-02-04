/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.preparator.cert.CertificateEntryPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.cert.CertificatePairSerializer;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.serializer.RecordSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "ChangeCertificateAction")
public class ChangeCertificateAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;
    @XmlTransient private List<Record> record_container = null;
    @XmlTransient private List<CertificateEntry> after_entries = null;

    public ChangeCertificateAction() {
        super();
    }

    public ChangeCertificateAction(String alias) {
        super(alias);
    }

    public ChangeCertificateAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public ChangeCertificateAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public ChangeCertificateAction(
            String alias, List<ProtocolMessage> container, List<Record> record_container) {
        super(alias);
        this.container = container;
        this.record_container = record_container;
    }

    public void setAfter_entries(List<CertificateEntry> after_entries) {
        this.after_entries = after_entries;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        ProtocolMessage message = container.get(0);
        message.setShouldPrepareDefault(false);

        Record record = record_container.get(0);
        record.setShouldPrepare(false);

        if (message instanceof CertificateMessage) {
            CertificateMessage certificate_message = (CertificateMessage) message;
            certificate_message.setCertificateEntryList(after_entries);

            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            for (CertificateEntry entry : after_entries) {
                CertificateEntryPreparator preparator =
                        new CertificateEntryPreparator(
                                state.getContext(getConnectionAlias()).getChooser(), entry);
                preparator.prepare();
                CertificatePairSerializer serializer =
                        new CertificatePairSerializer(entry, ProtocolVersion.TLS12);
                try {
                    stream.write(serializer.serialize());
                } catch (IOException ex) {
                    throw new ActionExecutionException(
                            "Could not write byte[] from CertificateEntry", ex);
                }
            }
            certificate_message.setCertificatesListBytes(stream.toByteArray());
            certificate_message.setCertificatesListLength(
                    certificate_message.getCertificatesListBytes().getValue().length);
            setExecuted(true);

            CertificateMessageSerializer serializer =
                    new CertificateMessageSerializer(
                            certificate_message,
                            state.getTlsContext(getConnectionAlias()).getSelectedProtocolVersion());
            certificate_message.setMessageContent(serializer.serializeHandshakeMessageContent());
            certificate_message.setLength(
                    certificate_message.getMessageContent().getValue().length);
            certificate_message.setCompleteResultingMessage(serializer.serialize());

            state.getContext(getConnectionAlias())
                    .setTalkingConnectionEndType(
                            state.getContext(getConnectionAlias())
                                    .getConnection()
                                    .getLocalConnectionEndType());
            CertificateMessageHandler handler =
                    certificate_message.getHandler(state.getTlsContext(getConnectionAlias()));
            handler.adjustContext(certificate_message);
            handler.adjustContextAfterSerialize(certificate_message);

            message.setAdjustContext(false);

            record.setProtocolMessageBytes(message.getCompleteResultingMessage());
            record.setCleanProtocolMessageBytes(message.getCompleteResultingMessage());
            record.setLength(record.getProtocolMessageBytes().getValue().length);

            RecordSerializer serializer2 = new RecordSerializer(record);
            record.setCompleteRecordBytes(serializer2.serialize());
        } else {
            throw new ActionExecutionException(
                    "Only certificate message can be changed!" + message);
        }
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

/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.preparator.cert.CertificateEntryPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.cert.CertificatePairSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildCertificateAction")
public class BuildCertificateAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;
    @XmlTransient private List<HandshakeMessageType> message_type_container = null;
    @XmlTransient private List<Boolean> message_length_container = null;
    @XmlTransient private List<CertificateEntry> entry_container = null;

    public BuildCertificateAction() {
        super();
    }

    public BuildCertificateAction(String alias) {
        super(alias);
    }

    public BuildCertificateAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildCertificateAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildCertificateAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setHandshakeMessageType(List<HandshakeMessageType> message_type_container) {
        this.message_type_container = message_type_container;
    }

    public void setMessageLength(List<Boolean> message_length_container) {
        this.message_length_container = message_length_container;
    }

    public void setCertificate(List<CertificateEntry> entry_container) {
        this.entry_container = entry_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        if (!(message_type_container.get(0) == HandshakeMessageType.CERTIFICATE)) {
            throw new ActionExecutionException(
                    "Error message type:" + message_type_container.get(0));
        }

        CertificateMessage message = new CertificateMessage();
        message.setShouldPrepareDefault(false);

        message.setType(HandshakeMessageType.CERTIFICATE.getValue());

        // For changing certificates later
        List<CertificateEntry> entry_list = new ArrayList<CertificateEntry>(entry_container);
        message.setCertificateEntryList(entry_list);

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (CertificateEntry entry : entry_list) {
            CertificateEntryPreparator preparator =
                    new CertificateEntryPreparator(state.getContext().getChooser(), entry);
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
        message.setCertificatesListBytes(stream.toByteArray());
        message.setCertificatesListLength(message.getCertificatesListBytes().getValue().length);

        CertificateMessageSerializer serializer =
                new CertificateMessageSerializer(message, ProtocolVersion.TLS12);
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        if (!message_length_container.get(0)) {
            throw new ActionExecutionException("Unsupported message length modification");
        }
        message.setCompleteResultingMessage(serializer.serialize());

        CertificateMessageHandler handler =
                new CertificateMessageHandler(state.getTlsContext(getConnectionAlias()));
        handler.adjustContext(message);
        message.setAdjustContext(false);

        container.add(message);
        setExecuted(true);
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    @Override
    public boolean executedAsPlanned() {
        return false;
    }
}

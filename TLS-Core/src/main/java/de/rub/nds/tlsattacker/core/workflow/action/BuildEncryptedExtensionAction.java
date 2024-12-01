/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.EncryptedExtensionsSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;

@XmlRootElement(name = "BuildEncryptedExtensionAction")
public class BuildEncryptedExtensionAction extends TlsAction {

    @XmlTransient private List<ProtocolMessage> container = null;

    @XmlTransient private List<HandshakeMessageType> message_type_container = null;
    @XmlTransient private List<Boolean> message_length_container = null;

    public BuildEncryptedExtensionAction() {}

    public BuildEncryptedExtensionAction(List<ProtocolMessage> container) {
        this.container = container;
    }

    public void setHandshakeMessageType(List<HandshakeMessageType> message_type_container) {
        this.message_type_container = message_type_container;
    }

    public void setMessageLength(List<Boolean> message_length_container) {
        this.message_length_container = message_length_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        EncryptedExtensionsMessage message = new EncryptedExtensionsMessage();
        message.setShouldPrepareDefault(false);
        message.setExtensionBytes(new byte[] {});
        message.setExtensionsLength(0);

        EncryptedExtensionsSerializer serializer = new EncryptedExtensionsSerializer(message);
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        if (!message_length_container.get(0)) {
            throw new ActionExecutionException("Unsupported modified message length");
        }
        message.setCompleteResultingMessage(serializer.serialize());

        container.add(message);
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

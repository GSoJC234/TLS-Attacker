/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom.extension;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public abstract class AddExtensionAction<T> extends ConnectionBoundAction {

    @XmlTransient protected List<ProtocolMessage> container = null;
    @XmlTransient protected List<T> extension_container = null;

    public AddExtensionAction() {
        super();
    }

    public AddExtensionAction(String alias) {
        super(alias);
    }

    public AddExtensionAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public AddExtensionAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public AddExtensionAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setExtensions(List<T> extension_container) {
        this.extension_container = extension_container;
    }

    protected abstract ExtensionMessage generateExtensionMessages(ConnectionEndType endType, State state);

    protected byte[] extensionMessageBytes(List<ExtensionMessage> messageList) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (ExtensionMessage message : messageList) {
            try {
                baos.write(message.getExtensionBytes().getValue());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return baos.toByteArray();
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        HandshakeMessage message = (HandshakeMessage) container.get(0);
        container.remove(0); // update message
        ConnectionEndType endType =
                state.getContext(getConnectionAlias()).getConnection().getLocalConnectionEndType();
        ExtensionMessage extensionMessage = generateExtensionMessages(endType, state);
        if (message.getExtensions() == null) {
            List<ExtensionMessage> messageList = new ArrayList<>();
            messageList.add(extensionMessage);
            message.setExtensions(messageList);
        } else {
            message.getExtensions().add(extensionMessage);
        }
        message.setExtensionBytes(extensionMessageBytes(message.getExtensions()));
        message.setExtensionsLength(message.getExtensionBytes().getValue().length);

        HandshakeMessageSerializer<?> serializer =
                message.getSerializer(state.getTlsContext(getConnectionAlias()));
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
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

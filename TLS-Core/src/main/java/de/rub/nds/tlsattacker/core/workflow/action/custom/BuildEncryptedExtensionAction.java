/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.EncryptedExtensionsHandler;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.EncryptedExtensionsSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.*;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildEncryptedExtensionAction")
public class BuildEncryptedExtensionAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;

    @XmlTransient private List<HandshakeMessageType> message_type_container = null;
    @XmlTransient private List<Boolean> message_length_container = null;
    @XmlTransient private List<List<?>> extension_container = null;

    public BuildEncryptedExtensionAction() {
        super();
    }

    public BuildEncryptedExtensionAction(String alias) {
        super(alias);
    }

    public BuildEncryptedExtensionAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildEncryptedExtensionAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildEncryptedExtensionAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setHandshakeMessageType(List<HandshakeMessageType> message_type_container) {
        this.message_type_container = message_type_container;
    }

    public void setMessageLength(List<Boolean> message_length_container) {
        this.message_length_container = message_length_container;
    }

    public void setExtension(List<List<?>> extension_container) {
        this.extension_container = extension_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        EncryptedExtensionsMessage message = new EncryptedExtensionsMessage();
        message.setShouldPrepareDefault(false);
        message.setType(message_type_container.get(0).getValue());
        message.setExtensionBytes(generateExtensionMessages());
        message.setExtensionsLength(message.getExtensionBytes().getValue().length);

        EncryptedExtensionsSerializer serializer = new EncryptedExtensionsSerializer(message);
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        if (!message_length_container.get(0)) {
            throw new ActionExecutionException("Unsupported modified message length");
        }
        message.setCompleteResultingMessage(serializer.serialize());

        Context context = state.getContext(getConnectionAlias());
        context.setTalkingConnectionEndType(context.getConnection().getLocalConnectionEndType());
        EncryptedExtensionsHandler handler =
                new EncryptedExtensionsHandler(state.getTlsContext(getConnectionAlias()));
        handler.adjustContext(message);
        message.setAdjustContext(false);

        container.add(message);
        setExecuted(true);
    }

    private byte[] generateExtensionMessages() {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        try {
            for (List<?> extension : extension_container) {
                Object element = extension.get(0);
                if (element instanceof NamedGroup) {
                    EllipticCurvesExtensionMessage message = new EllipticCurvesExtensionMessage();
                    message.setSupportedGroups(((NamedGroup) element).getValue());
                    message.setSupportedGroupsLength(
                            message.getSupportedGroups().getValue().length);
                    message.setExtensionType(ExtensionType.ELLIPTIC_CURVES.getValue());

                    EllipticCurvesExtensionSerializer serializer =
                            new EllipticCurvesExtensionSerializer(message);
                    message.setExtensionContent(serializer.serializeExtensionContent());
                    message.setExtensionLength(message.getExtensionContent().getValue().length);

                    byteStream.write(serializer.serialize());
                }
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return byteStream.toByteArray();
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

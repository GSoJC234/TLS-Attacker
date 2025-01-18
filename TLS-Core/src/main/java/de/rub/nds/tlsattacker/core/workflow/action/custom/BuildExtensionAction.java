/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildExtensionAction")
public class BuildExtensionAction extends ConnectionBoundAction {
    @XmlTransient private List<ProtocolMessage> container = null;
    @XmlTransient private List<List<?>> extension_container = null;

    public BuildExtensionAction() {
        super();
    }

    public BuildExtensionAction(String alias) {
        super(alias);
    }

    public BuildExtensionAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildExtensionAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildExtensionAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setExtensions(List<List<?>> extension_container) {
        this.extension_container = extension_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        HandshakeMessage message = (HandshakeMessage) container.get(0);
        container.remove(0); // update message
        ConnectionEndType endType =
                state.getContext(getConnectionAlias()).getConnection().getLocalConnectionEndType();
        List<ExtensionMessage> extensionMessageList = generateExtensionMessages(endType);
        message.setExtensions(extensionMessageList);
        message.setExtensionBytes(extensionMessageBytes(extensionMessageList));
        message.setExtensionsLength(message.getExtensionBytes().getValue().length);

        HandshakeMessageSerializer<?> serializer =
                message.getSerializer(state.getTlsContext(getConnectionAlias()));
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        message.setCompleteResultingMessage(serializer.serialize());

        container.add(message);
        setExecuted(true);
    }

    private byte[] extensionMessageBytes(List<ExtensionMessage> messageList) {
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

    private List<ExtensionMessage> generateExtensionMessages(ConnectionEndType endType) {
        List<ExtensionMessage> messageList = new ArrayList<ExtensionMessage>();

        for (List<?> extension : extension_container) {
            Object element = extension.get(0);
            if (element instanceof ProtocolVersion) {
                SupportedVersionsExtensionMessage message = new SupportedVersionsExtensionMessage();
                message.setSupportedVersions(((ProtocolVersion) element).getValue());
                if (endType == ConnectionEndType.CLIENT) {
                    message.setSupportedVersionsLength(
                            message.getSupportedVersions().getValue().length);
                }
                message.setExtensionType(ExtensionType.SUPPORTED_VERSIONS.getValue());

                SupportedVersionsExtensionSerializer serializer =
                        new SupportedVersionsExtensionSerializer(message);
                message.setExtensionContent(serializer.serializeExtensionContent());
                message.setExtensionLength(message.getExtensionContent().getValue().length);
                message.setExtensionBytes(serializer.serialize());

                messageList.add(message);
            } else if (element instanceof KeyShareEntry) {
                KeyShareEntrySerializer serializer =
                        new KeyShareEntrySerializer((KeyShareEntry) element);
                KeyShareExtensionMessage message = new KeyShareExtensionMessage();
                message.setExtensionType(ExtensionType.KEY_SHARE.getValue());

                List<KeyShareEntry> entryList = new ArrayList<>();
                entryList.add((KeyShareEntry) element);
                message.setKeyShareList(entryList);
                // message.setKeyShareListLength(entryList.size());
                message.setKeyShareListBytes(serializer.serialize());
                message.setKeyShareListLength(message.getKeyShareListBytes().getValue().length);

                KeyShareExtensionSerializer serializer2 =
                        new KeyShareExtensionSerializer(message, endType);
                message.setExtensionContent(serializer2.serializeExtensionContent());
                message.setExtensionLength(message.getExtensionContent().getValue().length);
                message.setExtensionBytes(serializer2.serialize());

                messageList.add(message);
            } else if (element instanceof NamedGroup) {
                EllipticCurvesExtensionMessage message = new EllipticCurvesExtensionMessage();
                message.setSupportedGroups(((NamedGroup) element).getValue());
                message.setSupportedGroupsLength(message.getSupportedGroups().getValue().length);
                message.setExtensionType(ExtensionType.ELLIPTIC_CURVES.getValue());

                EllipticCurvesExtensionSerializer serializer =
                        new EllipticCurvesExtensionSerializer(message);
                message.setExtensionContent(serializer.serializeExtensionContent());
                message.setExtensionLength(message.getExtensionContent().getValue().length);
                message.setExtensionBytes(serializer.serialize());

                messageList.add(message);
            } else if (element instanceof SignatureAndHashAlgorithm) {
                SignatureAndHashAlgorithmsExtensionMessage message =
                        new SignatureAndHashAlgorithmsExtensionMessage();
                message.setSignatureAndHashAlgorithms(
                        ((SignatureAndHashAlgorithm) element).getByteValue());
                message.setSignatureAndHashAlgorithmsLength(
                        message.getSignatureAndHashAlgorithms().getValue().length);
                message.setExtensionType(ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS.getValue());

                SignatureAndHashAlgorithmsExtensionSerializer serializer =
                        new SignatureAndHashAlgorithmsExtensionSerializer(message);
                message.setExtensionContent(serializer.serializeExtensionContent());
                message.setExtensionLength(message.getExtensionContent().getValue().length);
                message.setExtensionBytes(serializer.serialize());

                messageList.add(message);
            }
        }

        return messageList;
    }

    @Override
    public void reset() {}

    @Override
    public boolean executedAsPlanned() {
        return false;
    }
}

/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom.extension;

import de.rub.nds.protocol.exception.PreparationException;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKBinder;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PSKBinderSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PreSharedKeyExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "SetCHPreSharedKeyBinderAction")
public class SetCHPreSharedKeyBinderAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;
    @XmlTransient private List<byte[]> binderValues = null;

    public SetCHPreSharedKeyBinderAction() {
        super();
    }

    public SetCHPreSharedKeyBinderAction(String alias) {
        super(alias);
    }

    public SetCHPreSharedKeyBinderAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public SetCHPreSharedKeyBinderAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public SetCHPreSharedKeyBinderAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setBinderValues(List<byte[]> binderValues) {
        this.binderValues = binderValues;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        try {
            if (container == null || container.isEmpty()) {
                throw new ActionExecutionException("SetCHPreSharedKeyBinderAction: message container is empty");
            }
            if (binderValues == null || binderValues.isEmpty() || binderValues.get(0) == null) {
                throw new ActionExecutionException("SetCHPreSharedKeyBinderAction: binder value is empty");
            }

            ProtocolMessage protocolMessage = container.get(0);
            if (!(protocolMessage instanceof ClientHelloMessage)) {
                throw new ActionExecutionException("SetCHPreSharedKeyBinderAction requires a ClientHelloMessage");
            }

            ClientHelloMessage message = (ClientHelloMessage) protocolMessage;
            if (message.getExtensions() == null) {
                throw new ActionExecutionException("ClientHello has no extensions");
            }

            PreSharedKeyExtensionMessage pskExtension = null;
            int pskExtensionCount = 0;
            for (ExtensionMessage extension : message.getExtensions()) {
                if (extension instanceof PreSharedKeyExtensionMessage) {
                    pskExtension = (PreSharedKeyExtensionMessage) extension;
                    pskExtensionCount++;
                }
            }
            if (pskExtensionCount != 1) {
                throw new ActionExecutionException(
                        "Expected exactly one ClientHello pre_shared_key extension, found "
                                + pskExtensionCount);
            }
            if (pskExtension.getBinders() == null || pskExtension.getBinders().isEmpty()) {
                throw new ActionExecutionException("ClientHello pre_shared_key extension has no binders");
            }

            for (int i = 0; i < pskExtension.getBinders().size(); i++) {
                byte[] binderValue = binderValues.get(Math.min(i, binderValues.size() - 1));
                if (binderValue == null) {
                    throw new ActionExecutionException("SetCHPreSharedKeyBinderAction: binder value is null");
                }
                PSKBinder binder = pskExtension.getBinders().get(i);
                byte[] binderCopy = Arrays.copyOf(binderValue, binderValue.length);
                binder.setBinderEntry(binderCopy);
                binder.setBinderEntryLength(binderCopy.length);
            }

            prepareBinderListBytes(pskExtension);
            ConnectionEndType endType = ConnectionEndType.CLIENT;
            PreSharedKeyExtensionSerializer extensionSerializer =
                    new PreSharedKeyExtensionSerializer(pskExtension, endType);
            pskExtension.setExtensionContent(extensionSerializer.serializeExtensionContent());
            pskExtension.setExtensionLength(pskExtension.getExtensionContent().getValue().length);
            pskExtension.setExtensionBytes(extensionSerializer.serialize());

            message.setExtensionBytes(extensionMessageBytes(message.getExtensions()));
            message.setExtensionsLength(message.getExtensionBytes().getValue().length);

            TlsContext tlsContext = state.getTlsContext(getConnectionAlias());
            HandshakeMessageSerializer<?> serializer = message.getSerializer(tlsContext);
            message.setMessageContent(serializer.serializeHandshakeMessageContent());
            message.setLength(message.getMessageContent().getValue().length);
            message.setCompleteResultingMessage(serializer.serialize());

            container.remove(0);
            container.add(message);
            setExecuted(true);
        } catch (ActionExecutionException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new ActionExecutionException("Failed to set ClientHello PSK binder", e);
        }
    }

    private void prepareBinderListBytes(PreSharedKeyExtensionMessage message) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (PSKBinder binder : message.getBinders()) {
            PSKBinderSerializer serializer = new PSKBinderSerializer(binder);
            try {
                outputStream.write(serializer.serialize());
            } catch (IOException e) {
                throw new PreparationException("Could not serialize PSK binder", e);
            }
        }
        message.setBinderListBytes(outputStream.toByteArray());
        message.setBinderListLength(message.getBinderListBytes().getValue().length);
    }

    private byte[] extensionMessageBytes(List<ExtensionMessage> messages) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (ExtensionMessage message : messages) {
            try {
                outputStream.write(message.getExtensionBytes().getValue());
            } catch (IOException e) {
                throw new PreparationException("Could not serialize extension list", e);
            }
        }
        return outputStream.toByteArray();
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

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
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.EncryptedExtensionsSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildEncryptedExtensionAction")
public class BuildEncryptedExtensionAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;

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

    @Override
    public void execute(State state) throws ActionExecutionException {
        EncryptedExtensionsMessage message = new EncryptedExtensionsMessage();
        message.setShouldPrepareDefault(false);
        message.setType(HandshakeMessageType.ENCRYPTED_EXTENSIONS.getValue());

        EncryptedExtensionsSerializer serializer = new EncryptedExtensionsSerializer(message);
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        message.setCompleteResultingMessage(serializer.serialize());

        container.add(message);
        System.out.println("EncryptedExtension: " + message);
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

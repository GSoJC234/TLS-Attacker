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
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.ServerHelloDoneSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildServerHelloDoneAction")
public class BuildServerHelloDoneAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;
    @XmlTransient private List<HandshakeMessageType> type_container = null;

    public BuildServerHelloDoneAction() {
        super();
    }

    public BuildServerHelloDoneAction(String alias) {
        super(alias);
    }

    public BuildServerHelloDoneAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildServerHelloDoneAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildServerHelloDoneAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setHandshakeType(List<HandshakeMessageType> type_container) {
        this.type_container = type_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        ServerHelloDoneMessage message = new ServerHelloDoneMessage();
        message.setShouldPrepareDefault(false);
        if(type_container != null) {
            message.setType(type_container.get(0).getValue());
        } else {
            message.setType(HandshakeMessageType.SERVER_HELLO_DONE.getValue());
        }

        ServerHelloDoneSerializer serializer = message.getSerializer(state.getTlsContext(getConnectionAlias()));
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        message.setCompleteResultingMessage(serializer.serialize());

        container.add(message);
        setExecuted(true);
    }

    @Override
    public void reset() {}

    @Override
    public boolean executedAsPlanned() {
        return true;
    }
}

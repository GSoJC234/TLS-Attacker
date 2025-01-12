/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "UpdateDigestAction")
public class UpdateDigestAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;

    public UpdateDigestAction() {
        super();
    }

    public UpdateDigestAction(String alias) {
        super(alias);
    }

    public UpdateDigestAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public UpdateDigestAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public UpdateDigestAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        HandshakeMessage message = (HandshakeMessage) container.get(0);
        HandshakeMessageHandler handler =
                message.getHandler(state.getTlsContext(getConnectionAlias()));
        handler.updateDigest(message, true);
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

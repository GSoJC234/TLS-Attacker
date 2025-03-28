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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "UpdateContextAction")
public class UpdateContextAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;
    @XmlTransient private boolean isSent = false;

    public UpdateContextAction() {
        super();
    }

    public UpdateContextAction(String alias) {
        super(alias);
    }

    public UpdateContextAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public UpdateContextAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public UpdateContextAction(String alias, List<ProtocolMessage> container, boolean isSent) {
        super(alias);
        this.container = container;
        this.isSent = isSent;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        ProtocolMessage message = container.get(0);

        ProtocolMessageHandler handler =
                message.getHandler(state.getTlsContext(getConnectionAlias()));
        handler.updateDigest(message, true);

        if (isSent) {
            TlsContext context = state.getTlsContext(getConnectionAlias());
            context.setTalkingConnectionEndType(
                    context.getConnection().getLocalConnectionEndType());
        }
        handler.adjustContext(message);
        if (!(message instanceof FinishedMessage)) {
            // We do not consider after application data
            // For processing application data, this code should be revised
            handler.adjustContextAfterSerialize(message);
        }
        message.setAdjustContext(false);

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

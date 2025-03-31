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
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.Set;

@XmlRootElement(name = "CheckConnectionAction")
public class CheckConnectionAction extends ConnectionBoundAction {

    boolean isClosed = false;

    public CheckConnectionAction() {
        super();
    }

    public CheckConnectionAction(String alias) {
        super(alias);
    }

    public CheckConnectionAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public CheckConnectionAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());
        TcpTransportHandler handler =
                (TcpTransportHandler)
                        state.getTcpContext(getConnectionAlias()).getTransportHandler();
        this.isClosed = handler.getSocketState() == SocketState.CLOSED;
        if (this.isClosed) {
            LOGGER.info("Connection " + getConnectionAlias() + " is closed");
        } else {
            LOGGER.info("Connection " + getConnectionAlias() + " is open");
        }
        setExecuted(true);
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    @Override
    public boolean executedAsPlanned() {
        return isClosed;
    }
}

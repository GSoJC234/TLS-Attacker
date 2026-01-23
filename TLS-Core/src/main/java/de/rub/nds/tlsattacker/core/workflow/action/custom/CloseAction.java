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
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import java.util.Set;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;

@XmlRootElement(name = "CloseAction")
public class CloseAction extends ConnectionBoundAction {

    private static final Marker TEST_MARKER = MarkerManager.getMarker("TEST");

    public CloseAction() {
        super();
    }

    public CloseAction(String alias) {
        super(alias);
    }

    public CloseAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public CloseAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        Context context = state.getContext(getConnectionAlias());
        TransportHandler handler = context.getTransportHandler();

        if (handler instanceof ServerTcpTransportHandler) {
            SocketState socketSt =
                    ((TcpTransportHandler) handler)
                            .getSocketState(state.getConfig().isReceiveFinalTcpSocketStateWithTimeout());
            context.getTcpContext().setFinalSocketState(socketSt);
        } else if (handler instanceof ClientTcpTransportHandler) {
            state.deleteContext(getConnectionAlias());
        } else {
            context.getTcpContext().setFinalSocketState(SocketState.UNAVAILABLE);
        }

        try {
            context.getTransportHandler().closeConnection();
            LOGGER.debug(TEST_MARKER, "handler.closeConnection() called.");
        } catch (IOException ex) {
            LOGGER.debug(TEST_MARKER,
                    "Could not close connection for context: {}",
                    context.getConnection().getAlias());
            LOGGER.debug(TEST_MARKER, ex.getLocalizedMessage());
        }

        //state.deleteContext(connectionAlias);
        LOGGER.debug(TEST_MARKER, "Connection closed!");
        setExecuted(true);
    }

    @Override
    public void reset() {

    }

    @Override
    public boolean executedAsPlanned() {
        return true;
    }
}

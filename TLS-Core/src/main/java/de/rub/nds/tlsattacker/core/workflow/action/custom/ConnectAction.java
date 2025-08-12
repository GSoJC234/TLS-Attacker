/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.LayerStackFactory;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.IOException;
import java.util.Set;

@XmlRootElement(name = "ConnectAction")
public class ConnectAction extends ConnectionBoundAction  {

    @XmlTransient private String ip;
    @XmlTransient private int port;
    @XmlTransient private int connectionTimeOut;

    public ConnectAction() {
        super();
    }

    public ConnectAction(String alias) {
        super(alias);
    }

    public ConnectAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public ConnectAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void setConnectionTimeOut(int connectionTimeOut) {
        this.connectionTimeOut = connectionTimeOut;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        OutboundConnection connection = new OutboundConnection(this.connectionAlias, port, ip);
        connection.setIp(ip);
        connection.setConnectionTimeout(connectionTimeOut);
        connection.setTimeout(connectionTimeOut);
        connection.setTransportHandlerType(TransportHandlerType.TCP);
        connection.setUseIpv6(false);


        Context context = new Context(state, connection);
        LayerStack layerStack =
                LayerStackFactory.createLayerStack(state.getConfig().getDefaultLayerConfiguration(), context);
        context.setLayerStack(layerStack);
        state.addContext(context);

        context.setTransportHandler(TransportHandlerFactory.createTransportHandler(connection));
        try {
            context.getTransportHandler().initialize();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

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

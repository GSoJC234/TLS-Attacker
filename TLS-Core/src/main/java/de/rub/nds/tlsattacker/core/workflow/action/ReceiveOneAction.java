/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.ReceiveOneLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.printer.LogPrinter;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "ReceiveOne")
public class ReceiveOneAction extends CommonReceiveAction {

    private static final Logger LOGGER = LogManager.getLogger();
    protected List<ProtocolMessage> receivedMessage;

    public ReceiveOneAction() {
        super();
    }

    public ReceiveOneAction(String connectionAlias) {
        super(connectionAlias);
    }

    public ReceiveOneAction(String connectionAlias, List<ProtocolMessage> receivedMessage) {
        super(connectionAlias);
        this.receivedMessage = receivedMessage;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        LOGGER.debug("Receiving... (" + this.getClass().getSimpleName() + ")");
        List<LayerConfiguration<?>> layerConfigurations = createLayerConfiguration(state);
        getReceiveResult(tlsContext.getLayerStack(), layerConfigurations);
        setExecuted(true);
        LOGGER.debug(
                "Receive Expected: {}", LogPrinter.toHumanReadableOneLine(layerConfigurations));

        if (hasDefaultAlias()) {
            LOGGER.info(
                    "Received Messages: {}",
                    LogPrinter.toHumanReadableMultiLine(getLayerStackProcessingResult()));
        } else {
            LOGGER.info(
                    "Received Messages ({}): {}",
                    getConnectionAlias(),
                    LogPrinter.toHumanReadableMultiLine(getLayerStackProcessingResult()));
        }

        for (ProtocolMessage message : getReceivedMessages()) {
            message.setShouldPrepareDefault(false);
            receivedMessage.add(message);
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("ReceiveOne Action:\n");
        sb.append("Received Message:");
        if ((getReceivedMessages() != null) && (!getReceivedMessages().isEmpty())) {
            for (ProtocolMessage message : getReceivedMessages()) {
                sb.append(message.toCompactString());
                sb.append(", ");
            }
        } else {
            sb.append(" (no messages set)");
        }
        sb.append("\n");
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder(super.toCompactString());
        sb.append(" (");
        if (getReceivedMessages() != null && (!getReceivedMessages().isEmpty())) {
            sb.append(receivedMessage.get(0).toCompactString());
        }
        sb.append(")");
        return sb.toString();
    }

    @Override
    public boolean executedAsPlanned() {
        return getReceivedMessages().size() == 1;
    }

    @Override
    protected List<LayerConfiguration<?>> createLayerConfiguration(State state) {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());
        List<LayerConfiguration<?>> configurationList = new LinkedList<>();
        configurationList.add(
                new ReceiveOneLayerConfiguration(ImplementedLayers.SSL2, receivedMessage));
        configurationList.add(
                new ReceiveOneLayerConfiguration(ImplementedLayers.MESSAGE, receivedMessage));
        return ActionHelperUtil.sortAndAddOptions(
                tlsContext.getLayerStack(), false, getActionOptions(), configurationList);
    }
}

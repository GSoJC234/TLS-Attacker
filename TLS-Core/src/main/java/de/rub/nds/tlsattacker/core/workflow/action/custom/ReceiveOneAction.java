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
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerStackProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ReceiveOneLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.printer.LogPrinter;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.CommonReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;

@XmlRootElement(name = "ReceiveOne")
public class ReceiveOneAction extends CommonReceiveAction {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final Marker CERT_MARKER = MarkerManager.getMarker("CERT");

    protected List<ProtocolMessage> protocolMessages;
    protected List<Record> recordMessages;

    public ReceiveOneAction() {
        super();
    }

    public ReceiveOneAction(String connectionAlias) {
        super(connectionAlias);
    }

    public ReceiveOneAction(String connectionAlias, List<ProtocolMessage> protocolMessages) {
        super(connectionAlias);
        this.protocolMessages = protocolMessages;
    }

    public ReceiveOneAction(
            String connectionAlias,
            List<Record> recordMessages,
            List<ProtocolMessage> protocolMessages) {
        super(connectionAlias);
        this.protocolMessages = protocolMessages;
        this.recordMessages = recordMessages;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());
        tlsContext.getConnection().setTimeout(100000);
        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        LOGGER.info("Receiving... (" + this.getClass().getSimpleName() + ")");
        List<LayerConfiguration<?>> layerConfigurations = createLayerConfiguration(state);
        LayerStackProcessingResult result =
                getReceiveResult(tlsContext.getLayerStack(), layerConfigurations);
        setExecuted(true);
        LOGGER.info("Receive Expected: " + LogPrinter.toHumanReadableOneLine(layerConfigurations));

        if (hasDefaultAlias()) {
            LOGGER.info(CERT_MARKER,
                    "Received messages: \n{}\n",
                    LogPrinter.toHumanReadableMultiLineReverseOrder(getLayerStackProcessingResult()));
        } else {
            LOGGER.info(CERT_MARKER,
                    "Received messages ({}): \n{}\n",
                            getConnectionAlias(),
                            LogPrinter.toHumanReadableMultiLineReverseOrder(getLayerStackProcessingResult()));
        }

        if(! getReceivedMessages().isEmpty()){
            for (ProtocolMessage message : getReceivedMessages()) {
                message.setShouldPrepareDefault(false);
                protocolMessages.add(message);
            }
            for (Record record : getReceivedRecords()) {
                record.setShouldPrepare(false);
                recordMessages.add(record);
            }
        } else {
            throw new ActionExecutionException("No messages were received.");
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
            sb.append(protocolMessages.get(0).toCompactString());
        }
        sb.append(")");
        return sb.toString();
    }

    @Override
    public boolean executedAsPlanned() {
        return true;
    }

    @Override
    protected List<LayerConfiguration<?>> createLayerConfiguration(State state) {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());
        List<LayerConfiguration<?>> configurationList = new LinkedList<>();
        configurationList.add(
                new ReceiveOneLayerConfiguration(ImplementedLayers.SSL2, protocolMessages));
        configurationList.add(
                new ReceiveOneLayerConfiguration(ImplementedLayers.MESSAGE, protocolMessages));
        return ActionHelperUtil.sortAndAddOptions(
                tlsContext.getLayerStack(), false, getActionOptions(), configurationList);
    }
}

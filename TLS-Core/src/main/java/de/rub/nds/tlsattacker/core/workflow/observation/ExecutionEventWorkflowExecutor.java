/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.observation;

import de.rub.nds.tlsattacker.core.exceptions.SkipActionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.StructuredLogValueBuilder;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.custom.ReceiveOneAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler;
import java.io.IOException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes a simple workflow while emitting machine-readable send, receive, and receive-end
 * observations after each action.
 */
public class ExecutionEventWorkflowExecutor extends WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger(ExecutionEventWorkflowExecutor.class);
    private static final Logger PROTOCOL_TRACE_LOGGER =
            LogManager.getLogger("mta.scenario.session.ProtocolTrace");

    public ExecutionEventWorkflowExecutor(State state) {
        super(WorkflowExecutorType.DEFAULT, state);
    }

    @Override
    public void executeWorkflow() {
        state.getWorkflowTrace().reset();
        state.setStartTimestamp(System.currentTimeMillis());
        List<TlsAction> tlsActions = state.getWorkflowTrace().getTlsActions();
        int actionIndex = 0;
        for (TlsAction action : tlsActions) {
            boolean skipped = false;
            RuntimeException executionFailure = null;
            try {
                action.normalize();
                executeAction(action, state);
            } catch (SkipActionException ex) {
                skipped = true;
            } catch (RuntimeException ex) {
                executionFailure = ex;
                throw ex;
            } finally {
                emitProtocolTrace(action, actionIndex);
                emitExecutionEvents(action, actionIndex, skipped, executionFailure);
                actionIndex++;
            }
        }
        if (state.getWorkflowTrace().executedAsPlanned()) {
            LOGGER.info("Workflow executed as planned.");
        } else {
            LOGGER.info("Workflow was not executed as planned.");
        }
    }

    private void emitExecutionEvents(
            TlsAction action,
            int actionIndex,
            boolean skipped,
            RuntimeException executionFailure) {
        if (action instanceof SendAction) {
            SendAction sendAction = (SendAction) action;
            if (wasActuallySent(sendAction)) {
                emitMessageSentEvents(sendAction, actionIndex);
            }
            return;
        }

        if (!(action instanceof ReceiveOneAction)) {
            return;
        }
        ReceiveOneAction receiveAction = (ReceiveOneAction) action;

        List<ProtocolMessage> messages = receiveAction.getReceivedMessages();
        if (!isEmpty(messages)) {
            for (int messageIndex = 0; messageIndex < messages.size(); messageIndex++) {
                ExecutionEventEmitter.emit(
                        "TESTER",
                        "MESSAGE_RECEIVED",
                        "connectionId",
                        connectionId(action),
                        "actionIndex",
                        actionIndex,
                        "messageIndex",
                        messageIndex,
                        "message",
                        messageName(messages.get(messageIndex)));
            }
            return;
        }

        // A record without a decoded protocol message is deliberately left unclassified.
        if (!isEmpty(receiveAction.getReceivedRecords())) {
            return;
        }

        String reason = receiveFailureReason(executionFailure);
        if (reason == null && skipped) {
            reason = receiveEndReason(action);
        }
        if (reason != null) {
            ExecutionEventEmitter.emit(
                    "TESTER",
                    "RECEIVE_ENDED",
                    "connectionId",
                    connectionId(action),
                    "actionIndex",
                    actionIndex,
                    "reason",
                    reason);
        }
    }

    private static void emitMessageSentEvents(SendAction sendAction, int actionIndex) {
        List<ProtocolMessage> messages = sendAction.getSentMessages();
        if (!isEmpty(messages)) {
            for (int messageIndex = 0; messageIndex < messages.size(); messageIndex++) {
                ExecutionEventEmitter.emit(
                        "TESTER",
                        "MESSAGE_SENT",
                        "connectionId",
                        connectionId(sendAction),
                        "actionIndex",
                        actionIndex,
                        "messageIndex",
                        messageIndex,
                        "message",
                        messageName(messages.get(messageIndex)));
            }
            return;
        }

        // A send can consist only of explicitly configured TLS records.
        ExecutionEventEmitter.emit(
                "TESTER",
                "MESSAGE_SENT",
                "connectionId",
                connectionId(sendAction),
                "actionIndex",
                actionIndex,
                "recordCount",
                sendAction.getSentRecords().size());
    }

    private static String receiveFailureReason(Throwable failure) {
        Throwable current = failure;
        while (current != null) {
            if (current instanceof SocketTimeoutException) {
                return "TIMEOUT";
            }
            if (current instanceof SocketException) {
                return "SOCKET_EXCEPTION";
            }
            if (current instanceof IOException) {
                return "IO_EXCEPTION";
            }
            current = current.getCause();
        }
        return null;
    }

    private static boolean wasActuallySent(SendAction sendAction) {
        return sendAction.isExecuted()
                && sendAction.executedAsPlanned()
                && (!isEmpty(sendAction.getSentMessages()) || !isEmpty(sendAction.getSentRecords()));
    }

    private String receiveEndReason(TlsAction action) {
        String connectionId = connectionId(action);
        try {
            TransportHandler handler = state.getContext(connectionId).getTransportHandler();
            if (!(handler instanceof TcpTransportHandler)) {
                return "IO_EXCEPTION";
            }
            SocketState socketState = ((TcpTransportHandler) handler).getSocketState(false);
            switch (socketState) {
                case CLOSED:
                case PEER_WRITE_CLOSED:
                    return "PEER_CLOSED";
                case TIMEOUT:
                case UP:
                    return "TIMEOUT";
                case SOCKET_EXCEPTION:
                    return "SOCKET_EXCEPTION";
                case IO_EXCEPTION:
                case UNAVAILABLE:
                    return "IO_EXCEPTION";
                case DATA_AVAILABLE:
                default:
                    return null;
            }
        } catch (RuntimeException ex) {
            return "IO_EXCEPTION";
        }
    }

    private static String connectionId(TlsAction action) {
        if (action instanceof ConnectionBoundAction) {
            return ((ConnectionBoundAction) action).getConnectionAlias();
        }
        return "unknown";
    }

    private static void emitProtocolTrace(TlsAction action, int actionIndex) {
        if (action instanceof SendAction) {
            SendAction sendAction = (SendAction) action;
            List<ProtocolMessage> messages = sendAction.getSentMessages();
            if (isEmpty(messages)) {
                messages = sendAction.getConfiguredMessages();
            }
            List<Record> records = sendAction.getSentRecords();
            if (isEmpty(records)) {
                records = sendAction.getConfiguredRecords();
            }
            emitMessageTrace("SENT", actionIndex, messages, records);
        } else if (action instanceof ReceiveOneAction) {
            ReceiveOneAction receiveAction = (ReceiveOneAction) action;
            emitMessageTrace(
                    "RECEIVED",
                    actionIndex,
                    receiveAction.getReceivedMessages(),
                    receiveAction.getReceivedRecords());
        }
    }

    private static void emitMessageTrace(
            String direction,
            int actionIndex,
            List<ProtocolMessage> messages,
            List<Record> records) {
        int messageCount = messages == null ? 0 : messages.size();
        int recordCount = records == null ? 0 : records.size();
        int count = Math.max(messageCount, recordCount);
        for (int index = 0; index < count; index++) {
            ProtocolMessage message = index < messageCount ? messages.get(index) : null;
            byte[] bytes = messageBytes(message);
            if (bytes == null || bytes.length == 0) {
                bytes = recordBytes(index < recordCount ? records.get(index) : null);
            }
            PROTOCOL_TRACE_LOGGER.info(
                    formatProtocolTrace(direction, actionIndex, index, message, bytes));
        }
    }

    static String formatProtocolTrace(
            String direction, int actionIndex, int messageIndex, ProtocolMessage message) {
        return formatProtocolTrace(
                direction, actionIndex, messageIndex, message, messageBytes(message));
    }

    private static String formatProtocolTrace(
            String direction,
            int actionIndex,
            int messageIndex,
            ProtocolMessage message,
            byte[] bytes) {
        return "Protocol Message Value: direction="
                + direction
                + " actionIndex="
                + actionIndex
                + " messageIndex="
                + messageIndex
                + " message="
                + messageName(message)
                + " value="
                + (message == null ? "null" : messageValue(message))
                + " bytes="
                + (bytes == null ? "null" : StructuredLogValueBuilder.toHex(bytes));
    }

    private static boolean isEmpty(List<?> values) {
        return values == null || values.isEmpty();
    }

    private static byte[] messageBytes(ProtocolMessage message) {
        if (message == null) {
            return null;
        }
        return message.getCompleteResultingMessage() == null
                ? null
                : message.getCompleteResultingMessage().getValue();
    }

    private static byte[] recordBytes(Record record) {
        if (record == null) {
            return null;
        }
        byte[] bytes =
                record.getCleanProtocolMessageBytes() == null
                        ? null
                        : record.getCleanProtocolMessageBytes().getValue();
        if (bytes != null && bytes.length > 0) {
            return bytes;
        }
        bytes =
                record.getProtocolMessageBytes() == null
                        ? null
                        : record.getProtocolMessageBytes().getValue();
        if (bytes != null && bytes.length > 0) {
            return bytes;
        }
        return record.getCompleteRecordBytes() == null
                ? null
                : record.getCompleteRecordBytes().getValue();
    }

    private static String messageName(ProtocolMessage message) {
        if (message == null) {
            return "unknown";
        }
        String className = message.getClass().getSimpleName();
        if (className.endsWith("Message")) {
            return className.substring(0, className.length() - "Message".length());
        }
        return className;
    }

    private static String messageValue(ProtocolMessage message) {
        try {
            return message.toStructuredString();
        } catch (RuntimeException ex) {
            return new StructuredLogValueBuilder()
                    .add("contentType", message.getProtocolMessageType())
                    .add("description", messageName(message))
                    .toString();
        }
    }
}

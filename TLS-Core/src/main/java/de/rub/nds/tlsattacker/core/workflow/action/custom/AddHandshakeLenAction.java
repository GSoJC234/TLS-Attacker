/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "AddExtensionLenAction")
public class AddHandshakeLenAction extends ConnectionBoundAction {

    @XmlTransient protected List<ProtocolMessage> container = null;
    @XmlTransient protected List<Integer> handshake_len = null;

    public AddHandshakeLenAction() {
        super();
    }

    public AddHandshakeLenAction(String alias) {
        super(alias);
    }

    public AddHandshakeLenAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public AddHandshakeLenAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public AddHandshakeLenAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setHandshakeLen(List<Integer> extension_len) {
        this.handshake_len = extension_len;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        HandshakeMessage message = (HandshakeMessage) container.get(0);

        HandshakeMessageSerializer<?> serializer =
                message.getSerializer(state.getTlsContext(getConnectionAlias()));
        message.setMessageContent(serializer.serializeHandshakeMessageContent());

        int defaultLen = message.getMessageContent().getValue().length;
        int len = (handshake_len == null) ? defaultLen
                : SizeCalculator.calculate(handshake_len.get(0), defaultLen, HandshakeByteLength.HANDSHAKE_MESSAGE_LENGTH_FIELD_LENGTH);
        message.setLength(len);

        message.setCompleteResultingMessage(serializer.serialize());

        container.remove(0);
        container.add(message);
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

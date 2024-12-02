/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.crypto.MessageDigestCollector;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;

@XmlRootElement(name = "BuildHandshakeKeySetAction")
public class CalculateMessageDigestAction extends TlsAction {

    @XmlTransient private List<MessageDigestCollector> container;
    @XmlTransient private List<ProtocolMessage> protocolMessage_container;

    public CalculateMessageDigestAction() {}

    public CalculateMessageDigestAction(List<MessageDigestCollector> container) {
        this.container = container;
    }

    public void appendMessage(List<ProtocolMessage> message) {
        if (protocolMessage_container == null) {
            protocolMessage_container = message;
        } else {
            protocolMessage_container.addAll(message);
        }
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        MessageDigestCollector collector = new MessageDigestCollector();
        for (ProtocolMessage message : protocolMessage_container) {
            collector.append(message.getCompleteResultingMessage().getValue());
        }
        container.add(collector);
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

/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom.extension;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.custom.SizeCalculator;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "AddExtensionLenAction")
public class AddExtensionLenAction extends ConnectionBoundAction {

    @XmlTransient protected List<ProtocolMessage> container = null;
    @XmlTransient protected List<Integer> extension_len = null;

    public AddExtensionLenAction() {
        super();
    }

    public AddExtensionLenAction(String alias) {
        super(alias);
    }

    public AddExtensionLenAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public AddExtensionLenAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public AddExtensionLenAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setExtensionLen(List<Integer> extension_len) {
        this.extension_len = extension_len;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        HandshakeMessage message = (HandshakeMessage) container.get(0);
        if(message.getExtensionBytes() == null){
            setExecuted(true);
            return;
        }

        int defaultLen = message.getExtensionBytes().getValue().length;
        int len = (extension_len == null) ? defaultLen
                : SizeCalculator.calculate(extension_len.get(0), defaultLen, HandshakeByteLength.EXTENSION_LENGTH);
        message.setExtensionsLength(len);

        HandshakeMessageSerializer<?> serializer =
                message.getSerializer(state.getTlsContext(getConnectionAlias()));
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
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

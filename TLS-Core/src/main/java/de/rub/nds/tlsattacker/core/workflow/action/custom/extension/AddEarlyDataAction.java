/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EarlyDataExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EarlyDataExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PSKKeyExchangeModesExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.custom.SizeCalculator;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.List;
import java.util.Set;

public class AddEarlyDataAction extends AddExtensionAction<Integer>{

    public AddEarlyDataAction() {
        super();
    }

    public AddEarlyDataAction(String alias) {
        super(alias);
    }

    public AddEarlyDataAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
    }

    public AddEarlyDataAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public AddEarlyDataAction(String alias, List<ProtocolMessage> container) {
        super(alias, container);
    }

    @Override
    protected ExtensionMessage generateExtensionMessages(ConnectionEndType endType, State state) {
        EarlyDataExtensionMessage message = new EarlyDataExtensionMessage();
        message.setExtensionType(ExtensionType.EARLY_DATA.getValue());

        List<Integer> maxEarlyDataSize = extension_container;
        if (maxEarlyDataSize != null) {
            message.setMaxEarlyDataSize(maxEarlyDataSize.get(0));
            message.setNewSessionTicketExtension(true);
        }

        EarlyDataExtensionSerializer serializer =
                new EarlyDataExtensionSerializer(message);
        message.setExtensionContent(serializer.serializeExtensionContent());
        int defaultLen = message.getExtensionContent().getValue().length;
        int len = (extension_len == null) ? defaultLen
                : SizeCalculator.calculate(extension_len.get(0), defaultLen, HandshakeByteLength.EXTENSION_LENGTH);
        message.setExtensionLength(len);
        message.setExtensionBytes(serializer.serialize());

        return message;
    }
}

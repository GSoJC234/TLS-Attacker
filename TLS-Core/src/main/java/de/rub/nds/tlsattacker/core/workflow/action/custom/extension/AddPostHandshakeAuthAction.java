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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PostHandshakeAuthExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PostHandshakeAuthExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SupportedVersionsExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.custom.SizeCalculator;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "AddPostHandshakeAuthAction")
public class AddPostHandshakeAuthAction extends AddExtensionAction<Boolean> {


    public AddPostHandshakeAuthAction() {
        super();
    }

    public AddPostHandshakeAuthAction(String alias) {
        super(alias);
    }

    public AddPostHandshakeAuthAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
    }

    public AddPostHandshakeAuthAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public AddPostHandshakeAuthAction(String alias, List<ProtocolMessage> container) {
        super(alias, container);
    }

    @Override
    protected ExtensionMessage generateExtensionMessages(ConnectionEndType endType, State state) {
        PostHandshakeAuthExtensionMessage message = new PostHandshakeAuthExtensionMessage();
        message.setExtensionType(ExtensionType.POST_HANDSHAKE_AUTH.getValue());

        PostHandshakeAuthExtensionSerializer serializer =
                new PostHandshakeAuthExtensionSerializer(message);
        message.setExtensionContent(serializer.serializeExtensionContent());
        int defaultLen = message.getExtensionContent().getValue().length;
        int len = (extension_len == null) ? defaultLen
                : SizeCalculator.calculate(extension_len.get(0), defaultLen, HandshakeByteLength.EXTENSION_LENGTH);
        message.setExtensionLength(len);
        message.setExtensionBytes(serializer.serialize());

        System.out.println("SupportedVersionExtension: " + message);
        return message;
    }
}

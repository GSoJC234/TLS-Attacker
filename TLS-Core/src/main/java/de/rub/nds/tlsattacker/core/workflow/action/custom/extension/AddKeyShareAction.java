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
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeyShareEntrySerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeyShareExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.custom.SizeCalculator;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "AddKeyShareAction")
public class AddKeyShareAction extends AddExtensionAction<KeyShareEntry> {

    public AddKeyShareAction() {
        super();
    }

    public AddKeyShareAction(String alias) {
        super(alias);
    }

    public AddKeyShareAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
    }

    public AddKeyShareAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public AddKeyShareAction(String alias, List<ProtocolMessage> container) {
        super(alias, container);
    }

    @Override
    protected ExtensionMessage generateExtensionMessages(ConnectionEndType endType, State state) {
        KeyShareExtensionMessage message = new KeyShareExtensionMessage();
        message.setExtensionType(ExtensionType.KEY_SHARE.getValue());

        List<KeyShareEntry> keyShareEntryList = extension_container;
        message.setKeyShareList(keyShareEntryList);
        message.setKeyShareListBytes(keyShareEntrySerialize(keyShareEntryList));
        message.setKeyShareListLength(message.getKeyShareListBytes().getValue().length);

        KeyShareExtensionSerializer serializer = new KeyShareExtensionSerializer(message, endType);
        message.setExtensionContent(serializer.serializeExtensionContent());
        int defaultLen = message.getExtensionContent().getValue().length;
        int len = (extension_len == null) ? defaultLen
                : SizeCalculator.calculate(extension_len.get(0), defaultLen, HandshakeByteLength.EXTENSION_LENGTH);
        message.setExtensionLength(len);        message.setExtensionBytes(serializer.serialize());

        return message;
    }

    private byte[] keyShareEntrySerialize(List<KeyShareEntry> keyShareEntryList) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (KeyShareEntry entry : keyShareEntryList) {
            KeyShareEntrySerializer serializer = new KeyShareEntrySerializer(entry);
            try {
                outputStream.write(serializer.serialize());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return outputStream.toByteArray();
    }
}

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
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.KeyShareExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeyShareEntrySerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeyShareExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PSKKeyExchangeModesExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.custom.SizeCalculator;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "AddHRRKeyShareAction")
public class AddHRRKeyShareAction extends AddExtensionAction<NamedGroup> {

    public AddHRRKeyShareAction() {
        super();
    }

    public AddHRRKeyShareAction(String alias) {
        super(alias);
    }

    public AddHRRKeyShareAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
    }

    public AddHRRKeyShareAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public AddHRRKeyShareAction(String alias, List<ProtocolMessage> container) {
        super(alias, container);
    }

    @Override
    protected ExtensionMessage generateExtensionMessages(ConnectionEndType endType, State state) {
        KeyShareExtensionMessage message = new KeyShareExtensionMessage();
        message.setExtensionType(ExtensionType.KEY_SHARE.getValue());
        message.setRetryRequestMode(true);

        message.setKeyShareListBytes((extension_container.get(0)).getValue());
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

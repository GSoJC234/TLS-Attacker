/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom.extension;

import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PSKKeyExchangeModesExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SupportedVersionsExtensionSerializer;
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

@XmlRootElement(name = "AddPSKExchangeModeAction")
public class AddPSKExchangeModeAction extends AddExtensionAction<PskKeyExchangeMode> {

    public AddPSKExchangeModeAction() {
        super();
    }

    public AddPSKExchangeModeAction(String alias) {
        super(alias);
    }

    public AddPSKExchangeModeAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
    }

    public AddPSKExchangeModeAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public AddPSKExchangeModeAction(String alias, List<ProtocolMessage> container) {
        super(alias, container);
    }

    @Override
    protected ExtensionMessage generateExtensionMessages(ConnectionEndType endType, State state) {
        PSKKeyExchangeModesExtensionMessage message = new PSKKeyExchangeModesExtensionMessage();
        message.setExtensionType(ExtensionType.PSK_KEY_EXCHANGE_MODES.getValue());

        List<PskKeyExchangeMode> pskKeyExchangeModes = extension_container;
        message.setKeyExchangeModesListBytes(serializePskKeyExchangeModes(pskKeyExchangeModes));
        message.setKeyExchangeModesListLength(message.getKeyExchangeModesListBytes().getValue().length);

        PSKKeyExchangeModesExtensionSerializer serializer =
                new PSKKeyExchangeModesExtensionSerializer(message);
        message.setExtensionContent(serializer.serializeExtensionContent());
        int defaultLen = message.getExtensionContent().getValue().length;
        int len = (extension_len == null) ? defaultLen
                : SizeCalculator.calculate(extension_len.get(0), defaultLen, HandshakeByteLength.EXTENSION_LENGTH);
        message.setExtensionLength(len);
        message.setExtensionBytes(serializer.serialize());

        return message;
    }

    private byte[] serializePskKeyExchangeModes(List<PskKeyExchangeMode> modes) {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            for (PskKeyExchangeMode mode : modes) {
                outputStream.write(mode.getValue());
            }
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to serialize PskKeyExchangeModes", e);
        }
    }
}

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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SupportedVersionsExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "AddSupportedVersionAction")
public class AddSupportedVersionAction extends AddExtensionAction<ProtocolVersion> {

    public AddSupportedVersionAction() {
        super();
    }

    public AddSupportedVersionAction(String alias) {
        super(alias);
    }

    public AddSupportedVersionAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
    }

    public AddSupportedVersionAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public AddSupportedVersionAction(String alias, List<ProtocolMessage> container) {
        super(alias, container);
    }

    @Override
    protected ExtensionMessage generateExtensionMessages(ConnectionEndType endType, State state) {
        SupportedVersionsExtensionMessage message = new SupportedVersionsExtensionMessage();
        message.setExtensionType(ExtensionType.SUPPORTED_VERSIONS.getValue());

        List<ProtocolVersion> protocolVersionList = extension_container;
        message.setSupportedVersions(serializeProtocolVersion(protocolVersionList));
        if (endType == ConnectionEndType.CLIENT) {
            message.setSupportedVersionsLength(message.getSupportedVersions().getValue().length);
        }

        SupportedVersionsExtensionSerializer serializer =
                new SupportedVersionsExtensionSerializer(message);
        message.setExtensionContent(serializer.serializeExtensionContent());
        message.setExtensionLength(message.getExtensionContent().getValue().length);
        message.setExtensionBytes(serializer.serialize());

        System.out.println("SupportedVersionExtension: " + message);
        return message;
    }

    private byte[] serializeProtocolVersion(List<ProtocolVersion> versions) {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            for (ProtocolVersion version : versions) {
                outputStream.write(version.getValue());
            }
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to serialize CipherSuites", e);
        }
    }
}

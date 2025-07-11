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
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EllipticCurvesExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "AddSupportedGroupAction")
public class AddSupportedGroupAction extends AddExtensionAction<NamedGroup> {

    public AddSupportedGroupAction() {
        super();
    }

    public AddSupportedGroupAction(String alias) {
        super(alias);
    }

    public AddSupportedGroupAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
    }

    public AddSupportedGroupAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public AddSupportedGroupAction(String alias, List<ProtocolMessage> container) {
        super(alias, container);
    }

    @Override
    protected ExtensionMessage generateExtensionMessages(ConnectionEndType endType) {
        EllipticCurvesExtensionMessage message = new EllipticCurvesExtensionMessage();
        message.setExtensionType(ExtensionType.ELLIPTIC_CURVES.getValue());

        List<NamedGroup> namedGroupList = extension_container;
        message.setSupportedGroups(serializeNamedGroup(namedGroupList));
        message.setSupportedGroupsLength(message.getSupportedGroups().getValue().length);

        EllipticCurvesExtensionSerializer serializer =
                new EllipticCurvesExtensionSerializer(message);
        message.setExtensionContent(serializer.serializeExtensionContent());
        message.setExtensionLength(message.getExtensionContent().getValue().length);
        message.setExtensionBytes(serializer.serialize());

        System.out.println("SupportedGroupExtension: " + message);
        return message;
    }

    private byte[] serializeNamedGroup(List<NamedGroup> groups) {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            for (NamedGroup group : groups) {
                outputStream.write(group.getValue());
            }
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to serialize CipherSuites", e);
        }
    }
}

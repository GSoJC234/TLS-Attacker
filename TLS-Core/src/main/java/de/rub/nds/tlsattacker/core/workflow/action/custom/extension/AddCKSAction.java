/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom.extension;

import de.rub.nds.tlsattacker.core.constants.CksSigSpec;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CksExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CksExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.custom.SizeCalculator;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "AddCKSAction")
public class AddCKSAction extends AddExtensionAction<Integer> {

    public AddCKSAction() {
        super();
    }

    public AddCKSAction(String alias) {
        super(alias);
    }

    public AddCKSAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
    }

    public AddCKSAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public AddCKSAction(String alias, List<ProtocolMessage> container) {
        super(alias, container);
    }

    @Override
    protected ExtensionMessage generateExtensionMessages(ConnectionEndType endType, State state) {
        CksExtensionMessage message = new CksExtensionMessage();
        message.setExtensionType(ExtensionType.CKS.getValue());
        message.setCksSigSpecBytes(serializeCksSigSpecs(extension_container));

        CksExtensionSerializer serializer = new CksExtensionSerializer(message);
        message.setExtensionContent(serializer.serializeExtensionContent());
        int defaultLen = message.getExtensionContent().getValue().length;
        int len =
                (extension_len == null)
                        ? defaultLen
                        : SizeCalculator.calculate(
                                extension_len.get(0),
                                defaultLen,
                                HandshakeByteLength.EXTENSION_LENGTH);
        message.setExtensionLength(len);
        message.setExtensionBytes(serializer.serialize());
        return message;
    }

    private byte[] serializeCksSigSpecs(List<Integer> cksSigSpecs) {
        if (cksSigSpecs == null || cksSigSpecs.isEmpty()) {
            return new byte[] {CksSigSpec.NATIVE.getValue()};
        }

        byte[] cksSigSpecBytes = new byte[cksSigSpecs.size()];
        for (int i = 0; i < cksSigSpecs.size(); i++) {
            Integer cksSigSpec = cksSigSpecs.get(i);
            if (cksSigSpec == null) {
                throw new IllegalArgumentException("CKS sig spec value must not be null");
            }
            cksSigSpecBytes[i] = (byte) (cksSigSpec & 0xFF);
        }
        return cksSigSpecBytes;
    }
}

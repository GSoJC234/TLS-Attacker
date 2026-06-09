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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.RenegotiationInfoExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.custom.SizeCalculator;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "AddRenegotiationInfoAction")
public class AddRenegotiationInfoAction extends AddExtensionAction<byte[]> {

    public AddRenegotiationInfoAction() {
        super();
    }

    public AddRenegotiationInfoAction(String alias) {
        super(alias);
    }

    public AddRenegotiationInfoAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
    }

    public AddRenegotiationInfoAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public AddRenegotiationInfoAction(String alias, List<ProtocolMessage> container) {
        super(alias, container);
    }

    @Override
    protected ExtensionMessage generateExtensionMessages(ConnectionEndType endType, State state) {
        RenegotiationInfoExtensionMessage message = new RenegotiationInfoExtensionMessage();
        message.setExtensionType(ExtensionType.RENEGOTIATION_INFO.getValue());
        byte[] renegotiationInfo = resolveRenegotiationInfo(endType, state);
        message.setRenegotiationInfo(renegotiationInfo);
        message.setRenegotiationInfoLength(renegotiationInfo.length);

        RenegotiationInfoExtensionSerializer serializer =
                new RenegotiationInfoExtensionSerializer(message);
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

    private byte[] resolveRenegotiationInfo(ConnectionEndType endType, State state) {
        byte[] explicitRenegotiationInfo = concatenateExtensionContainer();
        if (explicitRenegotiationInfo != null) {
            return explicitRenegotiationInfo;
        }

        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());
        if (endType == ConnectionEndType.CLIENT) {
            if (tlsContext.getLastClientVerifyData() != null) {
                return tlsContext.getLastClientVerifyData();
            }
            return state.getConfig().getDefaultClientRenegotiationInfo();
        }

        if (tlsContext.getLastClientVerifyData() != null
                && tlsContext.getLastServerVerifyData() != null) {
            return concatenate(
                    tlsContext.getLastClientVerifyData(), tlsContext.getLastServerVerifyData());
        }
        return state.getConfig().getDefaultServerRenegotiationInfo();
    }

    private byte[] concatenateExtensionContainer() {
        if (extension_container == null || extension_container.isEmpty()) {
            return null;
        }

        int length = 0;
        boolean hasValue = false;
        for (byte[] value : extension_container) {
            if (value != null) {
                length += value.length;
                hasValue = true;
            }
        }
        if (!hasValue) {
            return null;
        }

        byte[] concatenated = new byte[length];
        int offset = 0;
        for (byte[] value : extension_container) {
            if (value != null) {
                System.arraycopy(value, 0, concatenated, offset, value.length);
                offset += value.length;
            }
        }
        return concatenated;
    }

    private byte[] concatenate(byte[] first, byte[] second) {
        byte[] concatenated = new byte[first.length + second.length];
        System.arraycopy(first, 0, concatenated, 0, first.length);
        System.arraycopy(second, 0, concatenated, first.length, second.length);
        return concatenated;
    }
}

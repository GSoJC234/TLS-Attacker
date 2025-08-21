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
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SignatureAndHashAlgorithmsExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.custom.SizeCalculator;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "AddSignatureAndHashAlgorithmAction")
public class AddSignatureAndHashAlgorithmAction
        extends AddExtensionAction<SignatureAndHashAlgorithm> {

    public AddSignatureAndHashAlgorithmAction() {
        super();
    }

    public AddSignatureAndHashAlgorithmAction(String alias) {
        super(alias);
    }

    public AddSignatureAndHashAlgorithmAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
    }

    public AddSignatureAndHashAlgorithmAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public AddSignatureAndHashAlgorithmAction(String alias, List<ProtocolMessage> container) {
        super(alias, container);
    }

    @Override
    protected ExtensionMessage generateExtensionMessages(ConnectionEndType endType, State state) {
        SignatureAndHashAlgorithmsExtensionMessage message =
                new SignatureAndHashAlgorithmsExtensionMessage();
        message.setExtensionType(ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS.getValue());

        List<SignatureAndHashAlgorithm> signatureAndHashAlgorithmList = extension_container;
        message.setSignatureAndHashAlgorithms(
                serializeSignatureAndHashAlgorithm(signatureAndHashAlgorithmList));
        message.setSignatureAndHashAlgorithmsLength(
                message.getSignatureAndHashAlgorithms().getValue().length);

        SignatureAndHashAlgorithmsExtensionSerializer serializer =
                new SignatureAndHashAlgorithmsExtensionSerializer(message);
        message.setExtensionContent(serializer.serializeExtensionContent());
        int defaultLen = message.getExtensionContent().getValue().length;
        int len = (extension_len == null) ? defaultLen
                : SizeCalculator.calculate(extension_len.get(0), defaultLen, HandshakeByteLength.EXTENSION_LENGTH);
        message.setExtensionLength(len);
        message.setExtensionBytes(serializer.serialize());

        System.out.println("SignatureAndHashAlgorithmExtension: " + message);
        return message;
    }

    private byte[] serializeSignatureAndHashAlgorithm(List<SignatureAndHashAlgorithm> algorithms) {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            for (SignatureAndHashAlgorithm algorithm : algorithms) {
                outputStream.write(algorithm.getByteValue());
            }
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to serialize CipherSuites", e);
        }
    }
}

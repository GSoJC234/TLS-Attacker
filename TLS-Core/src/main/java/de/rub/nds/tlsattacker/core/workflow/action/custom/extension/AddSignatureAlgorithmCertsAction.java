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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAlgorithmsCertExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SignatureAlgorithmsCertExtensionSerializer;
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

@XmlRootElement(name = "AddSignatureAlgorithmCertsAction")
public class AddSignatureAlgorithmCertsAction
        extends AddExtensionAction<SignatureAndHashAlgorithm> {

    private static final int LONG_SIGNATURE_ALGORITHM_LEN = 2000;

    public AddSignatureAlgorithmCertsAction() {
        super();
    }

    public AddSignatureAlgorithmCertsAction(String alias) {
        super(alias);
    }

    public AddSignatureAlgorithmCertsAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
    }

    public AddSignatureAlgorithmCertsAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public AddSignatureAlgorithmCertsAction(String alias, List<ProtocolMessage> container) {
        super(alias, container);
    }

    @Override
    protected ExtensionMessage generateExtensionMessages(ConnectionEndType endType, State state) {
        SignatureAlgorithmsCertExtensionMessage message =
                new SignatureAlgorithmsCertExtensionMessage();
        message.setExtensionType(ExtensionType.SIGNATURE_ALGORITHMS_CERT.getValue());

        List<SignatureAndHashAlgorithm> signatureAndHashAlgorithmList;
        if (super.longExtension) {
            signatureAndHashAlgorithmList = new ArrayList<>();
            for (int i = 0; i < extension_container.size() - 1; i++) {
                signatureAndHashAlgorithmList.add(extension_container.get(i));
            }
            for (int i = 0; i < LONG_SIGNATURE_ALGORITHM_LEN; i++) {
                signatureAndHashAlgorithmList.add(
                        extension_container.get(extension_container.size() - 1));
            }
        } else {
            signatureAndHashAlgorithmList = extension_container;
        }
        message.setSignatureAndHashAlgorithms(
                serializeSignatureAndHashAlgorithm(signatureAndHashAlgorithmList));
        message.setSignatureAndHashAlgorithmsLength(
                message.getSignatureAndHashAlgorithms().getValue().length);

        SignatureAlgorithmsCertExtensionSerializer serializer =
                new SignatureAlgorithmsCertExtensionSerializer(message);
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

        System.out.println("SignatureAlgorithmCertsExtension: " + message);
        return message;
    }

    private byte[] serializeSignatureAndHashAlgorithm(List<SignatureAndHashAlgorithm> algorithms) {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            for (SignatureAndHashAlgorithm algorithm : algorithms) {
                outputStream.write(algorithm.getByteValue());
            }
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to serialize SignatureAndHashAlgorithms", e);
        }
    }
}

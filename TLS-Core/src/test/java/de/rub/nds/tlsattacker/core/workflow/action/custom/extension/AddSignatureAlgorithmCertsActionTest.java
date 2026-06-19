/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAlgorithmsCertExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.List;
import org.junit.jupiter.api.Test;

public class AddSignatureAlgorithmCertsActionTest {

    @Test
    public void testGenerateExtensionMessage() {
        AddSignatureAlgorithmCertsAction action = new AddSignatureAlgorithmCertsAction();
        action.setExtensions(
                List.of(
                        SignatureAndHashAlgorithm.RSA_SHA256,
                        SignatureAndHashAlgorithm.ECDSA_SHA256));

        ExtensionMessage extensionMessage =
                action.generateExtensionMessages(ConnectionEndType.CLIENT, null);

        assertTrue(extensionMessage instanceof SignatureAlgorithmsCertExtensionMessage);
        SignatureAlgorithmsCertExtensionMessage message =
                (SignatureAlgorithmsCertExtensionMessage) extensionMessage;
        assertArrayEquals(
                ExtensionType.SIGNATURE_ALGORITHMS_CERT.getValue(),
                message.getExtensionType().getValue());
        assertEquals(6, message.getExtensionLength().getValue());
        assertEquals(4, message.getSignatureAndHashAlgorithmsLength().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("04010403"),
                message.getSignatureAndHashAlgorithms().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("00320006000404010403"),
                message.getExtensionBytes().getValue());
    }
}

/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import org.json.simple.parser.JSONParser;
import org.junit.jupiter.api.Test;

public class StructuredProtocolMessageTest {

    @Test
    public void rendersAlertEnumsInsteadOfTheirEncodedBytes() {
        AlertMessage message = new AlertMessage();
        message.setLevel(AlertLevel.FATAL.getValue());
        message.setDescription(AlertDescription.HANDSHAKE_FAILURE.getValue());

        assertEquals(
                "{\"contentType\":\"ALERT\",\"level\":\"FATAL\","
                        + "\"description\":\"HANDSHAKE_FAILURE\"}",
                message.toStructuredString());
    }

    @Test
    public void rendersClientHelloFieldsAndExtensionsAsSingleLineJson() {
        ClientHelloMessage message = new ClientHelloMessage();
        message.setLength(48);
        message.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        message.setRandom(new byte[] {0x00, 0x01, 0x02, 0x03});
        message.setSessionIdLength(0);
        message.setSessionId(new byte[0]);
        message.setCipherSuiteLength(4);
        message.setCipherSuites(new byte[] {0x13, 0x01, (byte) 0xC0, 0x2F});
        message.setCompressionLength(1);
        message.setCompressions(new byte[] {0x00});
        message.setExtensionsLength(8);

        SignatureAndHashAlgorithmsExtensionMessage signatureAlgorithms =
                new SignatureAndHashAlgorithmsExtensionMessage();
        signatureAlgorithms.setExtensionLength(4);
        signatureAlgorithms.setSignatureAndHashAlgorithmsLength(2);
        signatureAlgorithms.setSignatureAndHashAlgorithms(new byte[] {0x04, 0x03});
        message.addExtension(signatureAlgorithms);

        String value = message.toStructuredString();

        assertTrue(value.startsWith("{\"contentType\":\"HANDSHAKE\""));
        assertTrue(value.contains("\"handshakeType\":\"CLIENT_HELLO\""));
        assertTrue(value.contains("\"protocolVersion\":\"TLS12\""));
        assertTrue(value.contains("\"random\":\"00 01 02 03\""));
        assertTrue(
                value.contains(
                        "\"cipherSuites\":[\"TLS_AES_128_GCM_SHA256\","
                                + "\"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\"]"));
        assertTrue(value.contains("\"compressionMethods\":[\"NULL\"]"));
        assertTrue(
                value.contains(
                        "\"extensionType\":\"SIGNATURE_AND_HASH_ALGORITHMS\""));
        assertTrue(value.contains("\"signatureAlgorithms\":[\"ECDSA_SHA256\"]"));
        assertFalse(value.contains("\n"));
        assertDoesNotThrow(() -> new JSONParser().parse(value));
    }

    @Test
    public void preservesUnknownEnumValuesAsHex() {
        ClientHelloMessage message = new ClientHelloMessage();
        message.setCipherSuiteLength(2);
        message.setCipherSuites(new byte[] {(byte) 0xFE, (byte) 0xFE});
        message.setCompressionLength(1);
        message.setCompressions(new byte[] {(byte) 0x7F});

        String value = message.toStructuredString();

        assertTrue(value.contains("\"cipherSuites\":\"FE FE\""));
        assertTrue(value.contains("\"compressionMethods\":\"7F\""));
    }
}

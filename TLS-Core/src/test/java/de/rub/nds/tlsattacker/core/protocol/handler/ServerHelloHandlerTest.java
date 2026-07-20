/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.Test;

public class ServerHelloHandlerTest
        extends AbstractProtocolMessageHandlerTest<ServerHelloMessage, ServerHelloHandler> {

    private static final byte[] X25519_SERVER_SHARE =
            ArrayConverter.hexStringToByteArray(
                    "9c1b0a7421919a73cb57b3a0ad9d6805861a9c47e11df8639d25323b79ce201c");

    public ServerHelloHandlerTest() {
        super(ServerHelloMessage::new, ServerHelloHandler::new);
    }

    /** Test of adjustContext method, of class ServerHelloHandler. */
    @Test
    @Override
    public void testadjustContext() {
        ServerHelloMessage message = new ServerHelloMessage();
        message.setUnixTime(new byte[] {0, 1, 2});
        message.setRandom(new byte[] {0, 1, 2, 3, 4, 5});
        message.setSelectedCompressionMethod(CompressionMethod.DEFLATE.getValue());
        message.setSelectedCipherSuite(
                CipherSuite.TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384.getByteValue());
        message.setSessionId(new byte[] {6, 6, 6});
        message.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        handler.adjustContext(message);
        assertArrayEquals(new byte[] {0, 1, 2, 3, 4, 5}, context.getServerRandom());
        assertSame(CompressionMethod.DEFLATE, context.getSelectedCompressionMethod());
        assertArrayEquals(new byte[] {6, 6, 6}, context.getServerSessionId());
        assertArrayEquals(
                CipherSuite.TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384.getByteValue(),
                context.getSelectedCipherSuite().getByteValue());
        assertArrayEquals(
                ProtocolVersion.TLS12.getValue(), context.getSelectedProtocolVersion().getValue());
    }

    @Test
    public void testadjustContextTls13() {
        ServerHelloMessage message = new ServerHelloMessage();
        context.getConfig()
                .setDefaultKeySharePrivateKey(
                        NamedGroup.ECDH_X25519,
                        new BigInteger(
                                ArrayConverter.hexStringToByteArray(
                                        "03BD8BCA70C19F657E897E366DBE21A466E4924AF6082DBDF573827BCDDE5DEF")));
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        message.setUnixTime(new byte[] {0, 1, 2});
        message.setRandom(new byte[] {0, 1, 2, 3, 4, 5});
        message.setSelectedCompressionMethod(CompressionMethod.DEFLATE.getValue());
        message.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256.getByteValue());
        message.setSessionId(new byte[] {6, 6, 6});
        message.setProtocolVersion(ProtocolVersion.TLS13.getValue());
        addKeyShareExtension(message, NamedGroup.ECDH_X25519, X25519_SERVER_SHARE);
        handler.adjustContext(message);
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "EA2F968FD0A381E4B041E6D8DDBF6DA93DE4CEAC862693D3026323E780DB9FC3"),
                context.getHandshakeSecret());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "C56CAE0B1A64467A0E3A3337F8636965787C9A741B0DAB63E503076051BCA15C"),
                context.getClientHandshakeTrafficSecret());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "DBF731F5EE037C4494F24701FF074AD4048451C0E2803BC686AF1F2D18E861F5"),
                context.getServerHandshakeTrafficSecret());
    }

    @Test
    public void testadjustContextTls13PWD() {
        ServerHelloMessage message = new ServerHelloMessage();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        message.setUnixTime(new byte[] {0, 1, 2});
        message.setRandom(new byte[] {0, 1, 2, 3, 4, 5});
        message.setSelectedCompressionMethod(CompressionMethod.DEFLATE.getValue());
        message.setSelectedCipherSuite(
                CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256.getByteValue());
        message.setSessionId(new byte[] {6, 6, 6});
        message.setProtocolVersion(ProtocolVersion.TLS13.getValue());
        addKeyShareExtension(
                message,
                NamedGroup.BRAINPOOLP256R1,
                ArrayConverter.hexStringToByteArray(
                        "9EE17F2ECF74028F6C1FD70DA1D05A4A85975D7D270CAA6B8605F1C6EBB875BA87579167408F7C9E77842C2B3F3368A25FD165637E9B5D57760B0B704659B87420669244AA67CB00EA72C09B84A9DB5BB824FC3982428FCD406963AE080E677A48"));
        handler.adjustContext(message);
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "09E4B18F6B4F59BD8ADED8E875CD9B9A7694A8C5345EDB3381A47D1F860BF209"),
                context.getHandshakeSecret());
    }

    @Test
    public void testadjustContextTls13MissingKeyShareAndPskDoesNotUseStaleContext()
            throws Exception {
        ServerHelloMessage message = createTls13ServerHello();
        context.getConfig()
                .setDefaultKeySharePrivateKey(
                        NamedGroup.ECDH_X25519,
                        new BigInteger(
                                ArrayConverter.hexStringToByteArray(
                                        "03BD8BCA70C19F657E897E366DBE21A466E4924AF6082DBDF573827BCDDE5DEF")));
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setPsk(new byte[] {1, 2, 3, 4});
        context.getConfig().setUsePsk(true);
        context.setServerKeyShareStoreEntry(
                new KeyShareStoreEntry(NamedGroup.ECDH_X25519, X25519_SERVER_SHARE));

        handler.adjustContext(message);

        assertArrayEquals(
                deriveHandshakeSecret(new byte[32], new byte[0]), context.getHandshakeSecret());
    }

    @Test
    public void testadjustContextTls13WolfSsl560HrrP521MissingKeyShare()
            throws Exception {
        ServerHelloMessage message = createTls13ServerHello();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.getConfig().setTargetLibraryName("wolfSSL");
        context.getConfig().setTargetLibraryVersion("5.6.0");
        context.getConfig().setTargetRuntimePlatform("linux-amd64");
        processHelloRetryRequest(NamedGroup.SECP521R1);

        handler.adjustContext(message);

        assertArrayEquals(
                deriveHandshakeSecret(new byte[32], new byte[512]), context.getHandshakeSecret());
    }

    @Test
    public void testadjustContextTls13WolfSsl560WithoutHrrDoesNotSelectP521Model() {
        ServerHelloMessage message = createTls13ServerHello();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.getConfig().setTargetLibraryName("wolfSSL");
        context.getConfig().setTargetLibraryVersion("5.6.0");
        context.getConfig().setTargetRuntimePlatform("linux-amd64");
        context.setSelectedGroup(NamedGroup.SECP521R1);

        assertThrows(IllegalStateException.class, () -> handler.adjustContext(message));
    }

    @Test
    public void testadjustContextTls13WolfSsl560HrrP256DoesNotSelectP521Model() {
        ServerHelloMessage message = createTls13ServerHello();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.getConfig().setTargetLibraryName("wolfSSL");
        context.getConfig().setTargetLibraryVersion("5.6.0");
        context.getConfig().setTargetRuntimePlatform("linux-amd64");
        processHelloRetryRequest(NamedGroup.SECP256R1);

        assertThrows(IllegalStateException.class, () -> handler.adjustContext(message));
    }

    @Test
    public void testadjustContextTls13WolfSsl584HrrP521MissingKeyShare()
            throws Exception {
        ServerHelloMessage message = createTls13ServerHello();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.getConfig().setTargetLibraryName("wolfSSL");
        context.getConfig().setTargetLibraryVersion("5.8.4");
        context.getConfig().setTargetRuntimePlatform("linux-amd64");
        processHelloRetryRequest(NamedGroup.SECP521R1);

        handler.adjustContext(message);

        assertArrayEquals(
                deriveHandshakeSecret(new byte[32], new byte[578]), context.getHandshakeSecret());
    }

    @Test
    public void testadjustContextTls13WolfSsl582P256PskDheMissingKeyShare()
            throws Exception {
        ServerHelloMessage message = createTls13SelectedPskServerHello();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setPsk(new byte[] {1, 2, 3, 4});
        context.getConfig().setUsePsk(true);
        context.getConfig().setTargetLibraryName("wolfSSL");
        context.getConfig().setTargetLibraryVersion("5.8.2");
        context.getConfig().setTargetRuntimePlatform("linux-amd64");
        context.setClientPskKeyExchangeModes(List.of(PskKeyExchangeMode.PSK_DHE_KE));
        context.setClientKeyShareStoreEntryList(
                List.of(new KeyShareStoreEntry(NamedGroup.SECP256R1, new byte[] {1})));

        handler.adjustContext(message);

        assertArrayEquals(
                deriveHandshakeSecret(new byte[] {1, 2, 3, 4}, new byte[32]),
                context.getHandshakeSecret());
    }

    @Test
    public void testadjustContextTls13WolfSsl582PskKeDoesNotSelectP256Model()
            throws Exception {
        ServerHelloMessage message = createTls13SelectedPskServerHello();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setPsk(new byte[] {1, 2, 3, 4});
        context.getConfig().setUsePsk(true);
        context.getConfig().setTargetLibraryName("wolfSSL");
        context.getConfig().setTargetLibraryVersion("5.8.2");
        context.getConfig().setTargetRuntimePlatform("linux-amd64");
        context.setClientPskKeyExchangeModes(List.of(PskKeyExchangeMode.PSK_KE));
        context.setClientKeyShareStoreEntryList(
                List.of(new KeyShareStoreEntry(NamedGroup.SECP256R1, new byte[] {1})));

        handler.adjustContext(message);

        assertArrayEquals(
                deriveHandshakeSecret(new byte[] {1, 2, 3, 4}, new byte[0]),
                context.getHandshakeSecret());
    }

    @Test
    public void testadjustContextTls13WolfSsl582P521DoesNotSelectP256Model()
            throws Exception {
        ServerHelloMessage message = createTls13SelectedPskServerHello();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setPsk(new byte[] {1, 2, 3, 4});
        context.getConfig().setUsePsk(true);
        context.getConfig().setTargetLibraryName("wolfSSL");
        context.getConfig().setTargetLibraryVersion("5.8.2");
        context.getConfig().setTargetRuntimePlatform("linux-amd64");
        context.setClientPskKeyExchangeModes(List.of(PskKeyExchangeMode.PSK_DHE_KE));
        context.setClientKeyShareStoreEntryList(
                List.of(new KeyShareStoreEntry(NamedGroup.SECP521R1, new byte[] {1})));

        handler.adjustContext(message);

        assertArrayEquals(
                deriveHandshakeSecret(new byte[] {1, 2, 3, 4}, new byte[0]),
                context.getHandshakeSecret());
    }

    @Test
    public void testadjustContextTls13WolfSsl582NonLinuxDoesNotSelectP256Model()
            throws Exception {
        ServerHelloMessage message = createTls13SelectedPskServerHello();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setPsk(new byte[] {1, 2, 3, 4});
        context.getConfig().setUsePsk(true);
        context.getConfig().setTargetLibraryName("wolfSSL");
        context.getConfig().setTargetLibraryVersion("5.8.2");
        context.getConfig().setTargetRuntimePlatform("darwin-arm64");
        context.setClientPskKeyExchangeModes(List.of(PskKeyExchangeMode.PSK_DHE_KE));
        context.setClientKeyShareStoreEntryList(
                List.of(new KeyShareStoreEntry(NamedGroup.SECP256R1, new byte[] {1})));

        handler.adjustContext(message);

        assertArrayEquals(
                deriveHandshakeSecret(new byte[] {1, 2, 3, 4}, new byte[0]),
                context.getHandshakeSecret());
    }

    @Test
    public void testadjustContextTls13MissingKeyShareAndPskNonWolfSslMetadata()
            throws Exception {
        ServerHelloMessage message = createTls13ServerHello();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.getConfig().setTargetLibraryName("OpenSSL");
        context.getConfig().setTargetLibraryVersion("3.4.0");
        context.getConfig().setTargetExecutionMode("docker");
        context.getConfig().setTargetRuntimePlatform("linux-amd64");

        handler.adjustContext(message);

        assertArrayEquals(
                deriveHandshakeSecret(new byte[32], new byte[0]), context.getHandshakeSecret());
    }

    @Test
    public void testadjustContextTls13MissingKeyShareAndPskWolfSslMetadataUnresolved() {
        ServerHelloMessage message = createTls13ServerHello();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.getConfig().setTargetLibraryName("wolfSSL");
        context.getConfig().setTargetLibraryVersion("5.6.0");

        assertThrows(IllegalStateException.class, () -> handler.adjustContext(message));
    }

    @Test
    public void testadjustContextTls13WolfSsl584WithoutHrrDoesNotSelectP521Model()
            throws Exception {
        ServerHelloMessage message = createTls13ServerHello();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.getConfig().setTargetLibraryName("wolfSSL");
        context.getConfig().setTargetLibraryVersion("5.8.4");
        context.getConfig().setTargetRuntimePlatform("linux-amd64");
        context.setSelectedGroup(NamedGroup.SECP521R1);

        handler.adjustContext(message);

        assertArrayEquals(
                deriveHandshakeSecret(new byte[32], new byte[0]), context.getHandshakeSecret());
    }

    @Test
    public void testadjustContextTls13WolfSsl584HrrP256DoesNotSelectP521Model()
            throws Exception {
        ServerHelloMessage message = createTls13ServerHello();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.getConfig().setTargetLibraryName("wolfSSL");
        context.getConfig().setTargetLibraryVersion("5.8.4");
        context.getConfig().setTargetRuntimePlatform("linux-amd64");
        processHelloRetryRequest(NamedGroup.SECP256R1);

        handler.adjustContext(message);

        assertArrayEquals(
                deriveHandshakeSecret(new byte[32], new byte[0]), context.getHandshakeSecret());
    }

    private ServerHelloMessage createTls13ServerHello() {
        ServerHelloMessage message = new ServerHelloMessage();
        message.setUnixTime(new byte[] {0, 1, 2});
        message.setRandom(new byte[] {0, 1, 2, 3, 4, 5});
        message.setSelectedCompressionMethod(CompressionMethod.DEFLATE.getValue());
        message.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256.getByteValue());
        message.setSessionId(new byte[] {6, 6, 6});
        message.setProtocolVersion(ProtocolVersion.TLS13.getValue());
        return message;
    }

    private ServerHelloMessage createTls13SelectedPskServerHello() {
        ServerHelloMessage message = createTls13ServerHello();
        PreSharedKeyExtensionMessage selectedPsk = new PreSharedKeyExtensionMessage();
        selectedPsk.setSelectedIdentity(0);
        message.addExtension(selectedPsk);
        return message;
    }

    private void processHelloRetryRequest(NamedGroup selectedGroup) {
        ServerHelloMessage helloRetryRequest = createTls13ServerHello();
        helloRetryRequest.setRandom(ServerHelloMessage.getHelloRetryRequestRandom());
        helloRetryRequest.setCompleteResultingMessage(new byte[] {2});
        KeyShareEntry entry = new KeyShareEntry(selectedGroup, null);
        entry.setGroup(selectedGroup.getValue());
        KeyShareExtensionMessage extension = new KeyShareExtensionMessage();
        extension.setRetryRequestMode(true);
        extension.getKeyShareList().add(entry);
        helloRetryRequest.addExtension(extension);

        handler.adjustContext(helloRetryRequest);

        assertTrue(context.isHelloRetryRequestProcessed());
        assertSame(selectedGroup, context.getSelectedGroup());
    }

    private void addKeyShareExtension(
            ServerHelloMessage message, NamedGroup namedGroup, byte[] publicKey) {
        KeyShareEntry entry = new KeyShareEntry();
        entry.setGroup(namedGroup.getValue());
        entry.setPublicKey(publicKey);
        entry.setPublicKeyLength(publicKey.length);
        KeyShareExtensionMessage extension = new KeyShareExtensionMessage();
        extension.getKeyShareList().add(entry);
        message.addExtension(extension);
    }

    private byte[] deriveHandshakeSecret(byte[] psk, byte[] sharedSecret) throws Exception {
        HKDFAlgorithm hkdfAlgorithm =
                AlgorithmResolver.getHKDFAlgorithm(CipherSuite.TLS_AES_128_GCM_SHA256);
        DigestAlgorithm digestAlgorithm =
                AlgorithmResolver.getDigestAlgorithm(
                        ProtocolVersion.TLS13, CipherSuite.TLS_AES_128_GCM_SHA256);
        byte[] earlySecret = HKDFunction.extract(hkdfAlgorithm, new byte[0], psk);
        byte[] saltHandshakeSecret =
                HKDFunction.deriveSecret(
                        hkdfAlgorithm,
                        digestAlgorithm.getJavaName(),
                        earlySecret,
                        HKDFunction.DERIVED,
                        new byte[0]);
        return HKDFunction.extract(hkdfAlgorithm, saltHandshakeSecret, sharedSecret);
    }
}

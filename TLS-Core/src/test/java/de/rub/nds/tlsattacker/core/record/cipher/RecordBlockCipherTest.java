/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.TestRandomData;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class RecordBlockCipherTest {

    private TlsContext context;
    private RecordBlockCipher cipher;

    public RecordBlockCipherTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        Security.addProvider(new BouncyCastleProvider());
        UnlimitedStrengthEnabler.enable();
    }

    @Test
    public void testConstructors() throws NoSuchAlgorithmException, CryptoException {
        // This test just checks that the init() method will not break
        List<AliasedConnection> mixedConnections = new ArrayList<>();
        mixedConnections.add(new InboundConnection());
        mixedConnections.add(new OutboundConnection());
        context.setClientRandom(new byte[] { 0 });
        context.setServerRandom(new byte[] { 0 });
        context.setMasterSecret(new byte[] { 0 });
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            if (!suite.isSCSV() && AlgorithmResolver.getCipherType(suite) == CipherType.BLOCK) {
                context.setSelectedCipherSuite(suite);
                for (AliasedConnection con : mixedConnections) {
                    context.setConnection(con);
                    for (ProtocolVersion version : ProtocolVersion.values()) {
                        if (version == ProtocolVersion.SSL2 || version.isTLS13()) {
                            continue;
                        }
                        if (!suite.isSupportedInProtocol(version)) {
                            continue;
                        }
                        context.setSelectedProtocolVersion(version);
                        cipher = new RecordBlockCipher(context,
                            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                                context.getChooser().getSelectedCipherSuite(), KeySetGenerator.generateKeySet(context),
                                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
                    }
                }
            }
        }
    }

    @Test
    public void testEncryptTls10Client() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        byte[] data = ArrayConverter
            .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303");
        KeySet keySet = new KeySet();
        keySet
            .setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"));
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setCleanProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        cipher.encrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603010028"),
            record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(data, record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("7952A83507720317BEE172747A2A6C84759E6A33"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("03030303"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB57530030303037952A83507720317BEE172747A2A6C84759E6A3303030303"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E231DE35AD06AC17B8A26638290BB5846283B4788D8C42119BD"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E231DE35AD06AC17B8A26638290BB5846283B4788D8C42119BD"),
            record.getProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testDecryptTls10Client() throws NoSuchAlgorithmException, CryptoException {
        // This is effectively the testEncryptTls10() test in reverse
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        byte[] data = ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E231DE35AD06AC17B8A26638290BB5846283B4788D8C42119BD");
        KeySet keySet = new KeySet();
        keySet
            .setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"));
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        cipher.decrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603010028"),
            record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("7952A83507720317BEE172747A2A6C84759E6A33"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("03030303"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB57530030303037952A83507720317BEE172747A2A6C84759E6A3303030303"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E231DE35AD06AC17B8A26638290BB5846283B4788D8C42119BD"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E231DE35AD06AC17B8A26638290BB5846283B4788D8C42119BD"),
            record.getProtocolMessageBytes().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getCleanProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testDecryptTls10ClientOptionalPadding() throws NoSuchAlgorithmException, CryptoException {
        // This is effectively the testEncryptTls10() test in reverse
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        byte[] data = ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5ACCA58B3E4C6281AE3908AC88E21912AE7362CE4E0E16BDA5EFBBE8AB2997E6E2B5D4C9A66EF170E14F44648197BA16C0F50320D354A6AB830B89E7958967C207C64D6C4F16EBFEE9A7F1FC8B604F7890230C99F74C68DB414AF08F224C7D414B6E4697DB155564DAAE3E0AFC579909D73C702643B5AFD7E1D75F92EEBC8BBBCF71C4FA008EAFDA365AE87A3D77DE7DFBBA34CCF74C265C9B4B9B507A458AC9FE37D627F617AB8BFD49763FE896BEE835A229B389303320F7C0C5782E869C678925DA8A0B167E74DF21F9E024785C6D69E3E2C8D14FEB8EAC6BFC6B03851F12FA1D0F2D13B7BDCA9CBB554637B3077F14BB5063A53DC2DF8D4F69125929370FBA4BCE08A43D7D529EA59C1651D308B42F889A043445FF671C");
        KeySet keySet = new KeySet();
        keySet
            .setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"));
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        cipher.decrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000000160301000C"),
            record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1400000CCE92FBEC9131F48A"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("FD73CE51759C5E49089D4A6874CF4C7CFC578B90"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1400000CCE92FBEC9131F48AFD73CE51759C5E49089D4A6874CF4C7CFC578B90FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5ACCA58B3E4C6281AE3908AC88E21912AE7362CE4E0E16BDA5EFBBE8AB2997E6E2B5D4C9A66EF170E14F44648197BA16C0F50320D354A6AB830B89E7958967C207C64D6C4F16EBFEE9A7F1FC8B604F7890230C99F74C68DB414AF08F224C7D414B6E4697DB155564DAAE3E0AFC579909D73C702643B5AFD7E1D75F92EEBC8BBBCF71C4FA008EAFDA365AE87A3D77DE7DFBBA34CCF74C265C9B4B9B507A458AC9FE37D627F617AB8BFD49763FE896BEE835A229B389303320F7C0C5782E869C678925DA8A0B167E74DF21F9E024785C6D69E3E2C8D14FEB8EAC6BFC6B03851F12FA1D0F2D13B7BDCA9CBB554637B3077F14BB5063A53DC2DF8D4F69125929370FBA4BCE08A43D7D529EA59C1651D308B42F889A043445FF671C"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5ACCA58B3E4C6281AE3908AC88E21912AE7362CE4E0E16BDA5EFBBE8AB2997E6E2B5D4C9A66EF170E14F44648197BA16C0F50320D354A6AB830B89E7958967C207C64D6C4F16EBFEE9A7F1FC8B604F7890230C99F74C68DB414AF08F224C7D414B6E4697DB155564DAAE3E0AFC579909D73C702643B5AFD7E1D75F92EEBC8BBBCF71C4FA008EAFDA365AE87A3D77DE7DFBBA34CCF74C265C9B4B9B507A458AC9FE37D627F617AB8BFD49763FE896BEE835A229B389303320F7C0C5782E869C678925DA8A0B167E74DF21F9E024785C6D69E3E2C8D14FEB8EAC6BFC6B03851F12FA1D0F2D13B7BDCA9CBB554637B3077F14BB5063A53DC2DF8D4F69125929370FBA4BCE08A43D7D529EA59C1651D308B42F889A043445FF671C"),
            record.getProtocolMessageBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1400000CCE92FBEC9131F48A"),
            record.getCleanProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testEncryptTls11Client() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS11);
        KeySet keySet = new KeySet();
        keySet
            .setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(new byte[8]); // IV is not from KeyBlock
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used
        context.setRandom(new TestRandomData(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"))); // IV
        byte[] data = ArrayConverter
            .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303");
        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setCleanProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS11.getValue());
        cipher.encrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603020028"),
            record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(data, record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("223E43EF3310C5801FD0219E41EF6972738E96C6"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("03030303"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303223E43EF3310C5801FD0219E41EF6972738E96C603030303"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E235FDF3AEC315FD8629559C31FDF6F88E35EC40BF4B2A46473"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E235FDF3AEC315FD8629559C31FDF6F88E35EC40BF4B2A46473"),
            record.getProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testDecryptTls11Client() throws NoSuchAlgorithmException, CryptoException {
        // This is effectively the testEncryptTls11() test in reverse
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS11);
        KeySet keySet = new KeySet();
        keySet
            .setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(new byte[8]); // IV is not from KeyBlock
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        byte[] data = ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E235FDF3AEC315FD8629559C31FDF6F88E35EC40BF4B2A46473");
        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS11.getValue());
        cipher.decrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603020028"),
            record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("223E43EF3310C5801FD0219E41EF6972738E96C6"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("03030303"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303223E43EF3310C5801FD0219E41EF6972738E96C603030303"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E235FDF3AEC315FD8629559C31FDF6F88E35EC40BF4B2A46473"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E235FDF3AEC315FD8629559C31FDF6F88E35EC40BF4B2A46473"),
            record.getProtocolMessageBytes().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getCleanProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testDecryptTls11ClientOptionalPadding() throws NoSuchAlgorithmException, CryptoException {
        // This is effectively the testEncryptTls11() test in reverse
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS11);
        KeySet keySet = new KeySet();
        keySet
            .setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(new byte[8]); // IV is not from KeyBlock
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        byte[] data = ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E235FDF3AEC315FD8629559C31FDF6F88E34D7118CB3748357C79B51606C4B1ECEB");
        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS11.getValue());
        cipher.decrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603020028"),
            record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("223E43EF3310C5801FD0219E41EF6972738E96C6"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0B0B0B0B0B0B0B0B0B0B0B0B"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303223E43EF3310C5801FD0219E41EF6972738E96C60B0B0B0B0B0B0B0B0B0B0B0B"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E235FDF3AEC315FD8629559C31FDF6F88E34D7118CB3748357C79B51606C4B1ECEB"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E235FDF3AEC315FD8629559C31FDF6F88E34D7118CB3748357C79B51606C4B1ECEB"),
            record.getProtocolMessageBytes().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getCleanProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testEncryptTls12Client() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        KeySet keySet = new KeySet();
        keySet
            .setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(new byte[8]); // IV is not from KeyBlock
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used
        context.setRandom(new TestRandomData(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"))); // IV
        byte[] data = ArrayConverter
            .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303");
        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setCleanProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.encrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030028"),
            record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(data, record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("86878C26AA74D2576F5849AEF6CFED88BFD7FE7E"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("03030303"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB575300303030386878C26AA74D2576F5849AEF6CFED88BFD7FE7E03030303"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23658D0028D806AD6DCFB4A1C95523EE32182FE110528D80AE"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23658D0028D806AD6DCFB4A1C95523EE32182FE110528D80AE"),
            record.getProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testEncryptTls12ClientWithAddtionalPadding() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.getConfig().setDefaultAdditionalPadding(32);
        KeySet keySet = new KeySet();
        keySet
            .setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(new byte[8]); // IV is not from KeyBlock
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used
        context.setRandom(new TestRandomData(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"))); // IV
        byte[] data = ArrayConverter
            .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303");
        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setCleanProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.encrypt(record);

        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("232323232323232323232323232323232323232323232323232323232323232323232323"),
            record.getComputations().getPadding().getValue());
    }

    @Test
    public void testDecryptTls12Client() throws NoSuchAlgorithmException, CryptoException {
        // This is effectively the testEncryptTls12() test in reverse
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        KeySet keySet = new KeySet();
        keySet
            .setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(new byte[8]); // IV is not from KeyBlock
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        byte[] data = ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23658D0028D806AD6DCFB4A1C95523EE32182FE110528D80AE");
        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.decrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030028"),
            record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("86878C26AA74D2576F5849AEF6CFED88BFD7FE7E"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("03030303"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB575300303030386878C26AA74D2576F5849AEF6CFED88BFD7FE7E03030303"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23658D0028D806AD6DCFB4A1C95523EE32182FE110528D80AE"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23658D0028D806AD6DCFB4A1C95523EE32182FE110528D80AE"),
            record.getProtocolMessageBytes().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getCleanProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testDecryptTls12ClientOptionalPadding() throws NoSuchAlgorithmException, CryptoException {
        // This is effectively the testEncryptTls11() test in reverse
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        KeySet keySet = new KeySet();
        keySet
                .setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(new byte[8]); // IV is not from KeyBlock
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        byte[] data = ArrayConverter.hexStringToByteArray(
                "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23658D0028D806AD6DCFB4A1C95523EE328C31811DB00C9CBE6DE38CF0DC55B2C3");
        cipher = new RecordBlockCipher(context,
                new CipherState(context.getChooser().getSelectedProtocolVersion(),
                        context.getChooser().getSelectedCipherSuite(), keySet,
                        context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.decrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030028"),
                record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
                record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
                record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("86878C26AA74D2576F5849AEF6CFED88BFD7FE7E"),
                record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0B0B0B0B0B0B0B0B0B0B0B0B"),
                record.getComputations().getPadding().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
                        "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB575300303030386878C26AA74D2576F5849AEF6CFED88BFD7FE7E0B0B0B0B0B0B0B0B0B0B0B0B"),
                record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
                        "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23658D0028D806AD6DCFB4A1C95523EE328C31811DB00C9CBE6DE38CF0DC55B2C3"),
                record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
                        "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23658D0028D806AD6DCFB4A1C95523EE328C31811DB00C9CBE6DE38CF0DC55B2C3"),
                record.getProtocolMessageBytes().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
                record.getCleanProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testEncryptTls10Server() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new InboundConnection());
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.setClientRandom(
            ArrayConverter.hexStringToByteArray("03c08c3460b420bb3851d9d47acb933dbe70399bf6c92da33af01d4fb770e98c"));
        context.setServerRandom(
            ArrayConverter.hexStringToByteArray("78f0c84e04d3c23cad94aad61ccae23ce79bcd9d2d6953f8ccbe0e528c63a238"));
        context.setMasterSecret(ArrayConverter.hexStringToByteArray(
            "F81015161244782B3541E6020140556E4FFEA98C57FCF6CEC172CD8B577DC73CCDE4B724E07DB8687DDF327CD8A68891"));
        byte[] data = ArrayConverter
            .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303");
        KeySet keySet = new KeySet();
        keySet
            .setServerWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setServerWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setServerWriteIv(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"));
        keySet.setClientWriteIv(new byte[8]); // ServerSide is not used
        keySet.setClientWriteKey(new byte[24]); // ServerSide is not used
        keySet.setClientWriteMacSecret(new byte[20]); // ServerSide is not used

        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setCleanProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        cipher.encrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603010028"),
            record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(data, record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("7952A83507720317BEE172747A2A6C84759E6A33"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("03030303"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB57530030303037952A83507720317BEE172747A2A6C84759E6A3303030303"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E231DE35AD06AC17B8A26638290BB5846283B4788D8C42119BD"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E231DE35AD06AC17B8A26638290BB5846283B4788D8C42119BD"),
            record.getProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testDecryptTls10Server() throws NoSuchAlgorithmException, CryptoException {
        // This is effectively the testEncryptTls10() test in reverse
        context.setConnection(new OutboundConnection());
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        byte[] data = ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E231DE35AD06AC17B8A26638290BB5846283B4788D8C42119BD");
        KeySet keySet = new KeySet();
        keySet
            .setServerWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setServerWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setServerWriteIv(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"));
        keySet.setClientWriteIv(new byte[8]); // ClientSide is not used
        keySet.setClientWriteKey(new byte[24]); // ClientSide is not used
        keySet.setClientWriteMacSecret(new byte[20]); // ClientSide is not used

        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        cipher.decrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603010028"),
            record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("7952A83507720317BEE172747A2A6C84759E6A33"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("03030303"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB57530030303037952A83507720317BEE172747A2A6C84759E6A3303030303"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E231DE35AD06AC17B8A26638290BB5846283B4788D8C42119BD"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E231DE35AD06AC17B8A26638290BB5846283B4788D8C42119BD"),
            record.getProtocolMessageBytes().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getCleanProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testEncryptTls11Server() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new InboundConnection());
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS11);
        KeySet keySet = new KeySet();
        keySet
            .setServerWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setServerWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setServerWriteIv(new byte[8]); // IV is not from KeyBlock
        keySet.setClientWriteIv(new byte[8]); // ClientSide is not used
        keySet.setClientWriteKey(new byte[24]); // ClientSide is not used
        keySet.setClientWriteMacSecret(new byte[20]); // ClientSide is not used
        context.setRandom(new TestRandomData(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"))); // IV
        byte[] data = ArrayConverter
            .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303");
        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setCleanProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS11.getValue());
        cipher.encrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603020028"),
            record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(data, record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("223E43EF3310C5801FD0219E41EF6972738E96C6"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("03030303"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303223E43EF3310C5801FD0219E41EF6972738E96C603030303"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E235FDF3AEC315FD8629559C31FDF6F88E35EC40BF4B2A46473"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E235FDF3AEC315FD8629559C31FDF6F88E35EC40BF4B2A46473"),
            record.getProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testDecryptTls11Server() throws NoSuchAlgorithmException, CryptoException {
        // This is effectively the testEncryptTls11() test in reverse
        context.setConnection(new OutboundConnection());
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS11);
        KeySet keySet = new KeySet();
        keySet
            .setServerWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setServerWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setServerWriteIv(new byte[8]); // IV is not from KeyBlock
        keySet.setClientWriteIv(new byte[8]); // ClientSide is not used
        keySet.setClientWriteKey(new byte[24]); // ClientSide is not used
        keySet.setClientWriteMacSecret(new byte[20]); // ClientSide is not used

        byte[] data = ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E235FDF3AEC315FD8629559C31FDF6F88E35EC40BF4B2A46473");
        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS11.getValue());
        cipher.decrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603020028"),
            record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("223E43EF3310C5801FD0219E41EF6972738E96C6"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("03030303"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303223E43EF3310C5801FD0219E41EF6972738E96C603030303"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E235FDF3AEC315FD8629559C31FDF6F88E35EC40BF4B2A46473"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E235FDF3AEC315FD8629559C31FDF6F88E35EC40BF4B2A46473"),
            record.getProtocolMessageBytes().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getCleanProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testEncryptTls12Server() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new InboundConnection());
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        KeySet keySet = new KeySet();
        keySet
            .setServerWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setServerWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setServerWriteIv(new byte[8]); // IV is not from KeyBlock
        keySet.setClientWriteIv(new byte[8]); // ClientSide is not used
        keySet.setClientWriteKey(new byte[24]); // ClientSide is not used
        keySet.setClientWriteMacSecret(new byte[20]); // ClientSide is not used
        context.setRandom(new TestRandomData(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"))); // IV
        byte[] data = ArrayConverter
            .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303");
        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setCleanProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.encrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030028"),
            record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(data, record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("86878C26AA74D2576F5849AEF6CFED88BFD7FE7E"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("03030303"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB575300303030386878C26AA74D2576F5849AEF6CFED88BFD7FE7E03030303"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23658D0028D806AD6DCFB4A1C95523EE32182FE110528D80AE"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23658D0028D806AD6DCFB4A1C95523EE32182FE110528D80AE"),
            record.getProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testDecryptTls12Server() throws NoSuchAlgorithmException, CryptoException {
        // This is effectively the testEncryptTls12() test in reverse
        context.setConnection(new OutboundConnection());
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        KeySet keySet = new KeySet();
        keySet
            .setServerWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setServerWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setServerWriteIv(new byte[8]); // IV is not from KeyBlock
        keySet.setClientWriteIv(new byte[8]); // ClientSide is not used
        keySet.setClientWriteKey(new byte[24]); // ClientSide is not used
        keySet.setClientWriteMacSecret(new byte[20]); // ClientSide is not used

        byte[] data = ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23658D0028D806AD6DCFB4A1C95523EE32182FE110528D80AE");
        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.decrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030028"),
            record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("86878C26AA74D2576F5849AEF6CFED88BFD7FE7E"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("03030303"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB575300303030386878C26AA74D2576F5849AEF6CFED88BFD7FE7E03030303"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23658D0028D806AD6DCFB4A1C95523EE32182FE110528D80AE"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23658D0028D806AD6DCFB4A1C95523EE32182FE110528D80AE"),
            record.getProtocolMessageBytes().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getCleanProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testEncryptTls10WithEncryptThenMacClient() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        byte[] data = ArrayConverter
            .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303");
        KeySet keySet = new KeySet();
        keySet
            .setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"));
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setCleanProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        cipher.encrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getCiphertext().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603010030"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1A9BCCDD712329663F4065FA0E178F7A434676BE"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0707070707070707"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB57530030303030707070707070707"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE3621A9BCCDD712329663F4065FA0E178F7A434676BE"),
            record.getProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testDecryptTls10WithEncryptThenMacClient() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        byte[] data = ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE3621A9BCCDD712329663F4065FA0E178F7A434676BE");
        KeySet keySet = new KeySet();
        keySet
            .setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"));
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        cipher.decrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getCiphertext().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603010030"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1A9BCCDD712329663F4065FA0E178F7A434676BE"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0707070707070707"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB57530030303030707070707070707"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getCleanProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testEncryptTls11WithEncryptThenMacClient() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS11);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        byte[] data = ArrayConverter
            .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303");
        KeySet keySet = new KeySet();
        keySet
            .setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(new byte[0]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used
        context.setRandom(new TestRandomData(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"))); // IV

        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setCleanProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS11.getValue());
        cipher.encrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getCiphertext().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603020038"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("BE44B61CE4B722E0A741C12A74D50019A38C91B1"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0707070707070707"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB57530030303030707070707070707"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362BE44B61CE4B722E0A741C12A74D50019A38C91B1"),
            record.getProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testDecryptTls11WithEncryptThenMacClient() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS11);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        byte[] data = ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362BE44B61CE4B722E0A741C12A74D50019A38C91B1");
        KeySet keySet = new KeySet();
        keySet
            .setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(new byte[0]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS11.getValue());
        cipher.decrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603020038"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("BE44B61CE4B722E0A741C12A74D50019A38C91B1"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0707070707070707"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB57530030303030707070707070707"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getCleanProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testEncryptTls12WithEncryptThenMacClient() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        byte[] data = ArrayConverter
            .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303");
        KeySet keySet = new KeySet();
        keySet
            .setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(new byte[0]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used
        context.setRandom(new TestRandomData(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"))); // IV

        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setCleanProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.encrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getCiphertext().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030038"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("4920C96B8BD457549DA1B0908E13FA3EDD02211B"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0707070707070707"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB57530030303030707070707070707"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE3624920C96B8BD457549DA1B0908E13FA3EDD02211B"),
            record.getProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testDecryptTls12WithEncryptThenMacClient() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        byte[] data = ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE3624920C96B8BD457549DA1B0908E13FA3EDD02211B");
        KeySet keySet = new KeySet();
        keySet
            .setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(new byte[0]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.decrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030038"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("4920C96B8BD457549DA1B0908E13FA3EDD02211B"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0707070707070707"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB57530030303030707070707070707"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getCleanProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testEncryptTls10WithEncryptThenMacServer() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        byte[] data = ArrayConverter
            .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303");
        KeySet keySet = new KeySet();
        keySet
            .setServerWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setServerWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setServerWriteIv(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"));
        keySet.setClientWriteIv(new byte[8]); // ClientSide is not used
        keySet.setClientWriteKey(new byte[24]); // ClientSide is not used
        keySet.setClientWriteMacSecret(new byte[20]); // ClientSide is not used

        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setCleanProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        cipher.encrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getCiphertext().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603010030"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1A9BCCDD712329663F4065FA0E178F7A434676BE"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0707070707070707"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB57530030303030707070707070707"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE3621A9BCCDD712329663F4065FA0E178F7A434676BE"),
            record.getProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testDecryptTls10WithEncryptThenMacServer() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        byte[] data = ArrayConverter.hexStringToByteArray(
            "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE3621A9BCCDD712329663F4065FA0E178F7A434676BE");
        KeySet keySet = new KeySet();
        keySet
            .setServerWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setServerWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setServerWriteIv(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"));
        keySet.setClientWriteIv(new byte[8]); // ClientSide is not used
        keySet.setClientWriteKey(new byte[24]); // ClientSide is not used
        keySet.setClientWriteMacSecret(new byte[20]); // ClientSide is not used

        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        cipher.decrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getCiphertext().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603010030"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1A9BCCDD712329663F4065FA0E178F7A434676BE"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0707070707070707"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB57530030303030707070707070707"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getCleanProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testEncryptTls11WithEncryptThenMacServer() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS11);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        byte[] data = ArrayConverter
            .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303");
        KeySet keySet = new KeySet();
        keySet
            .setServerWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setServerWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setServerWriteIv(new byte[0]);
        keySet.setClientWriteIv(new byte[8]); // ClientSide is not used
        keySet.setClientWriteKey(new byte[24]); // ClientSide is not used
        keySet.setClientWriteMacSecret(new byte[20]); // ClientSide is not used
        context.setRandom(new TestRandomData(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"))); // IV

        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setCleanProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS11.getValue());
        cipher.encrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getCiphertext().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603020038"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("BE44B61CE4B722E0A741C12A74D50019A38C91B1"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0707070707070707"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB57530030303030707070707070707"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362BE44B61CE4B722E0A741C12A74D50019A38C91B1"),
            record.getProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testDecryptTls11WithEncryptThenMacServer() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS11);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        byte[] data = ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362BE44B61CE4B722E0A741C12A74D50019A38C91B1");
        KeySet keySet = new KeySet();
        keySet
            .setServerWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setServerWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setServerWriteIv(new byte[0]);
        keySet.setClientWriteIv(new byte[8]); // ClientSide is not used
        keySet.setClientWriteKey(new byte[24]); // ClientSide is not used
        keySet.setClientWriteMacSecret(new byte[20]); // ClientSide is not used

        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS11.getValue());
        cipher.decrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603020038"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("BE44B61CE4B722E0A741C12A74D50019A38C91B1"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0707070707070707"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB57530030303030707070707070707"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getCleanProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testEncryptTls12WithEncryptThenMacServer() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        byte[] data = ArrayConverter
            .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303");
        KeySet keySet = new KeySet();
        keySet
            .setServerWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setServerWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setServerWriteIv(new byte[0]);
        keySet.setClientWriteIv(new byte[8]); // ClientSide is not used
        keySet.setClientWriteKey(new byte[24]); // ClientSide is not used
        keySet.setClientWriteMacSecret(new byte[20]); // ClientSide is not used
        context.setRandom(new TestRandomData(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"))); // IV

        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setCleanProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.encrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getCiphertext().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030038"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("4920C96B8BD457549DA1B0908E13FA3EDD02211B"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0707070707070707"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB57530030303030707070707070707"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE3624920C96B8BD457549DA1B0908E13FA3EDD02211B"),
            record.getProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testDecryptTls12WithEncryptThenMacServer() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        byte[] data = ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE3624920C96B8BD457549DA1B0908E13FA3EDD02211B");
        KeySet keySet = new KeySet();
        keySet
            .setServerWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setServerWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setServerWriteIv(new byte[0]);
        keySet.setClientWriteIv(new byte[8]); // ClientSide is not used
        keySet.setClientWriteKey(new byte[24]); // ClientSide is not used
        keySet.setClientWriteMacSecret(new byte[20]); // ClientSide is not used

        cipher = new RecordBlockCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.decrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getAeadSalt());
        assertNull(record.getComputations().getGcmNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030038"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23A5B8C98C4E2DE362"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"),
            record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"),
            record.getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("4920C96B8BD457549DA1B0908E13FA3EDD02211B"),
            record.getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0707070707070707"),
            record.getComputations().getPadding().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB57530030303030707070707070707"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getCleanProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }
}

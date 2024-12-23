/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import static de.rub.nds.tlsattacker.core.constants.Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS;
import static de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeyBlockParser.AEAD_IV_LENGTH;

import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.crypto.KeyShareCalculator;
import de.rub.nds.tlsattacker.core.crypto.MessageDigestCollector;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.math.BigInteger;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildHandshakeKeySet")
public class BuildHandshakeKeySetAction extends ConnectionBoundAction {

    @XmlTransient private List<KeySet> container;
    @XmlTransient private List<ProtocolVersion> version_container;
    @XmlTransient private List<CipherSuite> cipher_suite_container;
    @XmlTransient private List<NamedGroup> namedGroup_container;
    @XmlTransient private List<byte[]> public_key_container;
    @XmlTransient private List<byte[]> private_key_container;
    @XmlTransient private List<MessageDigestCollector> message_digest_collector_container;

    public BuildHandshakeKeySetAction() {
        super();
    }

    public BuildHandshakeKeySetAction(String alias) {
        super(alias);
    }

    public BuildHandshakeKeySetAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildHandshakeKeySetAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildHandshakeKeySetAction(String alias, List<KeySet> container) {
        super(alias);
        this.container = container;
    }

    public void setProtocolVersion(List<ProtocolVersion> version_container) {
        this.version_container = version_container;
    }

    public void setSelectedCipherSuite(List<CipherSuite> cipher_suite_container) {
        this.cipher_suite_container = cipher_suite_container;
    }

    public void setNamedgroup(List<NamedGroup> namedgroup_container) {
        this.namedGroup_container = namedgroup_container;
    }

    public void setPublicKey(List<byte[]> public_key_container) {
        this.public_key_container = public_key_container;
    }

    public void setPrivateKey(List<byte[]> private_key_container) {
        this.private_key_container = private_key_container;
    }

    public void setMessageDigestCollector(
            List<MessageDigestCollector> message_digest_collector_container) {
        this.message_digest_collector_container = message_digest_collector_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext context = state.getTlsContext(getConnectionAlias());

        ProtocolVersion version = version_container.get(0);
        CipherSuite cipherSuite = cipher_suite_container.get(0);
        MessageDigestCollector messageDigestCollector = message_digest_collector_container.get(0);
        NamedGroup namedGroup = namedGroup_container.get(0);
        byte[] publicKey = public_key_container.get(0);
        byte[] privateKey = private_key_container.get(0);

        HKDFAlgorithm hkdfAlgorithm = AlgorithmResolver.getHKDFAlgorithm(cipherSuite);
        DigestAlgorithm digestAlgo = AlgorithmResolver.getDigestAlgorithm(version, cipherSuite);

        try {
            byte[] sharedSecret =
                    KeyShareCalculator.computeSharedSecret(
                            namedGroup, new BigInteger(privateKey), publicKey);
            byte[] handshakeSecret =
                    HKDFunction.extract(hkdfAlgorithm, new byte[] {}, sharedSecret);
            context.setHandshakeSecret(handshakeSecret);

            byte[] clientHandshakeTrafficSecret =
                    HKDFunction.deriveSecret(
                            hkdfAlgorithm,
                            digestAlgo.getJavaName(),
                            handshakeSecret,
                            HKDFunction.CLIENT_HANDSHAKE_TRAFFIC_SECRET,
                            messageDigestCollector.getRawBytes());
            context.setClientHandshakeTrafficSecret(clientHandshakeTrafficSecret);

            byte[] serverHandshakeTrafficSecret =
                    HKDFunction.deriveSecret(
                            hkdfAlgorithm,
                            digestAlgo.getJavaName(),
                            handshakeSecret,
                            HKDFunction.SERVER_HANDSHAKE_TRAFFIC_SECRET,
                            messageDigestCollector.getRawBytes());
            context.setServerHandshakeTrafficSecret(serverHandshakeTrafficSecret);

            CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(cipherSuite);
            KeySet keySet = new KeySet(HANDSHAKE_TRAFFIC_SECRETS);

            keySet.setClientWriteKey(
                    HKDFunction.expandLabel(
                            hkdfAlgorithm,
                            clientHandshakeTrafficSecret,
                            HKDFunction.KEY,
                            new byte[] {},
                            cipherAlg.getKeySize()));
            LOGGER.debug("Client write key: {}", keySet.getClientWriteKey());
            keySet.setServerWriteKey(
                    HKDFunction.expandLabel(
                            hkdfAlgorithm,
                            serverHandshakeTrafficSecret,
                            HKDFunction.KEY,
                            new byte[] {},
                            cipherAlg.getKeySize()));
            LOGGER.debug("Server write key: {}", keySet.getServerWriteKey());
            keySet.setClientWriteIv(
                    HKDFunction.expandLabel(
                            hkdfAlgorithm,
                            clientHandshakeTrafficSecret,
                            HKDFunction.IV,
                            new byte[] {},
                            AEAD_IV_LENGTH));
            LOGGER.debug("Client write IV: {}", keySet.getClientWriteIv());
            keySet.setServerWriteIv(
                    HKDFunction.expandLabel(
                            hkdfAlgorithm,
                            serverHandshakeTrafficSecret,
                            HKDFunction.IV,
                            new byte[] {},
                            AEAD_IV_LENGTH));
            LOGGER.debug("Server write IV: {}", keySet.getServerWriteIv());
            keySet.setServerWriteMacSecret(new byte[0]);
            keySet.setClientWriteMacSecret(new byte[0]);

            context.setkeySetHandshake(keySet);
            context.setActiveClientKeySetType(HANDSHAKE_TRAFFIC_SECRETS);
            context.setActiveServerKeySetType(HANDSHAKE_TRAFFIC_SECRETS);
            container.add(keySet);
        } catch (CryptoException e) {
            throw new RuntimeException(e);
        }
        setExecuted(true);
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    @Override
    public boolean executedAsPlanned() {
        return true;
    }
}

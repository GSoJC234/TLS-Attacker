/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "GetPreMasterSecretAction")
public class GetPreMasterSecretAction extends ConnectionBoundAction {

    @XmlTransient private List<byte[]> container = null;
    @XmlTransient private List<ProtocolMessage> message_container = null;
    @XmlTransient private List<byte[]> privateKey_container = null;

    public GetPreMasterSecretAction() {
        super();
    }

    public GetPreMasterSecretAction(String alias) {
        super(alias);
    }

    public GetPreMasterSecretAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public GetPreMasterSecretAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public GetPreMasterSecretAction(String alias, List<byte[]> container) {
        super(alias);
        this.container = container;
    }

    public void setMessage_container(List<ProtocolMessage> message_container) {
        this.message_container = message_container;
    }

    public void setPrivateKey_container(List<byte[]> privateKey_container) {
        this.privateKey_container = privateKey_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());

        RSAClientKeyExchangeMessage message =
                (RSAClientKeyExchangeMessage) message_container.get(0);

        byte[] privateKeyPem = privateKey_container.get(0);
        byte[] preMasterSecret = getPreMasterSecret(message, privateKeyPem);
        tlsContext.setPreMasterSecret(preMasterSecret);
        LOGGER.info("PreMaster Secret: " + Arrays.toString(preMasterSecret));
        container.add(preMasterSecret);
    }

    private byte[] getPreMasterSecret(RSAClientKeyExchangeMessage message, byte[] privateKeyPem) {
        byte[] premasterSecret = null;

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyPem);
        KeyFactory keyFactory = null;
        BigInteger modulus = null;
        BigInteger privateExponent = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            if (privateKey instanceof RSAPrivateCrtKey) {
                RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) privateKey;
                modulus = rsaPrivateKey.getModulus(); // N 값
                privateExponent = rsaPrivateKey.getPrivateExponent(); // d 값
            } else {
                throw new ActionExecutionException("Not a RSA Private Key.");
            }

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new ActionExecutionException("Could not create RSA private key", e);
        }

        message.prepareComputations();
        message.getComputations().setModulus(modulus);
        message.getComputations().setPrivateKey(privateExponent);

        int keyByteLength =
                message.getComputations().getModulus().getValue().bitLength() / Bits.IN_A_BYTE;

        // For RSA, the PublicKey field actually contains the encrypted
        // premaster secret
        LOGGER.debug("Decrypting premasterSecret");
        int randomByteLength = keyByteLength - HandshakeByteLength.PREMASTER_SECRET - 1;
        // decrypt premasterSecret
        byte[] paddedPremasterSecret = decryptPremasterSecret(message, modulus, privateExponent);
        LOGGER.debug("PaddedPremaster: {}", ArrayConverter.bytesToHexString(paddedPremasterSecret));
        if (randomByteLength < paddedPremasterSecret.length && randomByteLength > 0) {
            premasterSecret =
                    Arrays.copyOfRange(
                            paddedPremasterSecret, randomByteLength, paddedPremasterSecret.length);
            premasterSecret = manipulatePremasterSecret(premasterSecret);
            message.getComputations().setPremasterSecret(premasterSecret);
            if (premasterSecret.length > 2) {
                message.getComputations()
                        .setPremasterSecretProtocolVersion(
                                Arrays.copyOfRange(premasterSecret, 0, 2));
                LOGGER.debug(
                        "PMS Protocol Version {}",
                        message.getComputations().getPremasterSecretProtocolVersion().getValue());
            } else {
                LOGGER.warn("Decrypted PMS is not long enough to contain protocol version bytes");
            }
        } else {
            LOGGER.warn("RandomByteLength too short! Using empty premasterSecret!");
            premasterSecret = new byte[0];
        }

        return premasterSecret;
    }

    public byte[] decryptPremasterSecret(
            RSAClientKeyExchangeMessage message, BigInteger modulus, BigInteger privateExponent) {
        BigInteger bigIntegerEncryptedPremasterSecret =
                new BigInteger(1, message.getPublicKey().getValue());
        if (modulus.equals(BigInteger.ZERO)) {
            LOGGER.warn("RSA modulus is zero, returning new byte[0] as decryptedPremasterSecret");
            return new byte[0];
        }
        // Make sure that the private key is not negative
        BigInteger decrypted =
                bigIntegerEncryptedPremasterSecret.modPow(privateExponent.abs(), modulus.abs());
        return decrypted.toByteArray();
    }

    protected byte[] manipulatePremasterSecret(byte[] premasterSecret) {
        return premasterSecret; // Nothing to do here
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

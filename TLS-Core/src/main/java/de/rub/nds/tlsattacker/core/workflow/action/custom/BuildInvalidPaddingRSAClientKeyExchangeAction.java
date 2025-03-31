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
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.RSAClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.x509attacker.x509.model.publickey.PublicKeyContent;
import de.rub.nds.x509attacker.x509.model.publickey.X509RsaPublicKey;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildInvalidPaddingRSAClientKeyExchangeAction")
public class BuildInvalidPaddingRSAClientKeyExchangeAction extends ConnectionBoundAction {

    @XmlTransient protected List<ProtocolMessage> container = null;
    @XmlTransient private List<byte[]> clientRandom = null;
    @XmlTransient private List<byte[]> serverRandom = null;
    @XmlTransient private List<byte[]> nonce = null;
    @XmlTransient private List<PublicKeyContent> publicKeyContainer = null;

    public BuildInvalidPaddingRSAClientKeyExchangeAction() {
        super();
    }

    public BuildInvalidPaddingRSAClientKeyExchangeAction(String alias) {
        super(alias);
    }

    public BuildInvalidPaddingRSAClientKeyExchangeAction(
            Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildInvalidPaddingRSAClientKeyExchangeAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildInvalidPaddingRSAClientKeyExchangeAction(
            String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setClientRandom(List<byte[]> clientRandom) {
        this.clientRandom = clientRandom;
    }

    public void setServerRandom(List<byte[]> serverRandom) {
        this.serverRandom = serverRandom;
    }

    public void setNonce(List<byte[]> nonce) {
        this.nonce = nonce;
    }

    public void setPublicKeyContainer(List<PublicKeyContent> publicKeyContainer) {
        this.publicKeyContainer = publicKeyContainer;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        RSAClientKeyExchangeMessage message = new RSAClientKeyExchangeMessage();
        message.setShouldPrepareDefault(false);

        message.setType(HandshakeMessageType.CLIENT_KEY_EXCHANGE.getValue());
        message.prepareComputations();
        message.getComputations()
                .setClientServerRandom(
                        ArrayConverter.concatenate(clientRandom.get(0), serverRandom.get(0)));

        X509RsaPublicKey publicKeyContent = (X509RsaPublicKey) publicKeyContainer.get(0);
        message.getComputations().setModulus(publicKeyContent.getModulus().getValue());
        message.getComputations()
                .setPublicExponent(publicKeyContent.getPublicExponent().getValue());

        BigInteger modulus = message.getComputations().getModulus().getValue();

        int ceiledModulusByteLength =
                (int) Math.ceil((double) modulus.bitLength() / Bits.IN_A_BYTE);
        int randomByteLength = ceiledModulusByteLength - HandshakeByteLength.PREMASTER_SECRET - 3;

        byte[] padding = null;

        if (randomByteLength > 0) {
            padding = new byte[randomByteLength];
            try {
                SecureRandom secureRandom = SecureRandom.getInstanceStrong();
                secureRandom.nextBytes(padding);
            } catch (NoSuchAlgorithmException e) {
                LOGGER.error("Secure random generator algorithm is not found");
            }
            ArrayConverter.makeArrayNonZero(padding);
        } else {
            padding = new byte[0];
        }
        message.getComputations().setPadding(padding);
        message.getComputations().setPremasterSecret(generatePremasterSecret(message));

        message.getComputations()
                .setPlainPaddedPremasterSecret(
                        ArrayConverter.concatenate(
                                new byte[] {0x00, 0x02},
                                padding,
                                new byte[] {0x00},
                                message.getComputations().getPremasterSecret().getValue()));

        byte[] paddedPremasterSecret =
                message.getComputations().getPlainPaddedPremasterSecret().getValue();

        if (paddedPremasterSecret.length == 0) {
            LOGGER.warn("paddedPremasterSecret length is zero length!");
            paddedPremasterSecret = new byte[] {0};
        }

        BigInteger biPaddedPremasterSecret = new BigInteger(1, paddedPremasterSecret);
        BigInteger biEncrypted =
                biPaddedPremasterSecret.modPow(
                        message.getComputations().getPublicExponent().getValue().abs(),
                        message.getComputations().getModulus().getValue().abs());

        // compute invalid padding
        // (c * s^e) mod N
        BigInteger attackValue = BigInteger.valueOf(65337);
        BigInteger wrongEncrypted =
                biEncrypted
                        .multiply(attackValue)
                        .modPow(
                                message.getComputations().getPublicExponent().getValue().abs(),
                                message.getComputations().getModulus().getValue().abs());
        byte[] encrypted =
                ArrayConverter.bigIntegerToByteArray(wrongEncrypted, ceiledModulusByteLength, true);
        message.setPublicKey(encrypted);
        message.setPublicKeyLength(message.getPublicKey().getValue().length);

        RSAClientKeyExchangeSerializer serializer =
                new RSAClientKeyExchangeSerializer(message, ProtocolVersion.TLS12);
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        message.setCompleteResultingMessage(serializer.serialize());

        container.add(message);
        setExecuted(true);
    }

    protected byte[] generatePremasterSecret(RSAClientKeyExchangeMessage message) {
        message.getComputations()
                .setPremasterSecretProtocolVersion(ProtocolVersion.TLS12.getValue());
        byte[] tempPremasterSecret =
                new byte[HandshakeByteLength.PREMASTER_SECRET - HandshakeByteLength.VERSION];
        try {
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            secureRandom.nextBytes(tempPremasterSecret);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Secure random generator algorithm is not found");
        }
        return ArrayConverter.concatenate(
                message.getComputations().getPremasterSecretProtocolVersion().getValue(),
                tempPremasterSecret);
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

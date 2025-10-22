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
import de.rub.nds.protocol.crypto.CyclicGroup;
import de.rub.nds.protocol.crypto.ec.*;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.ECDHClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.math.BigInteger;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildECDHClientKeyExchangeAction")
public class BuildECDHClientKeyExchangeAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;
    @XmlTransient private List<HandshakeMessageType> type_container = null;
    @XmlTransient private List<byte[]> ec_private_container = null;

    public BuildECDHClientKeyExchangeAction() {
        super();
    }

    public BuildECDHClientKeyExchangeAction(String alias) {
        super(alias);
    }

    public BuildECDHClientKeyExchangeAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildECDHClientKeyExchangeAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildECDHClientKeyExchangeAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setHandshakeType(List<HandshakeMessageType> type_container) {
        this.type_container = type_container;
    }

    public void setECPrivateKey(List<byte[]> ec_private_container) {
        this.ec_private_container = ec_private_container;
    }


    @Override
    public void execute(State state) throws ActionExecutionException {
        Chooser chooser = state.getTlsContext(getConnectionAlias()).getChooser();

        ECDHClientKeyExchangeMessage message = new ECDHClientKeyExchangeMessage();
        message.setShouldPrepareDefault(false);
        message.prepareComputations();

        if(type_container != null) {
            message.setType(type_container.get(0).getValue());
        } else {
            message.setType(HandshakeMessageType.CLIENT_KEY_EXCHANGE.getValue());
        }
        if (ec_private_container != null) {
            BigInteger privateKey = new BigInteger(1, ec_private_container.get(0));
            message.getComputations().setPrivateKey(privateKey);
        }

        NamedGroup usedGroup = chooser.getSelectedNamedGroup();
        CyclicGroup<?> group = usedGroup.getGroupParameters().getGroup();
        EllipticCurve curve;
        if (group instanceof EllipticCurve) {
            curve = (EllipticCurve) group;
        } else {
            LOGGER.warn("Selected group is not an EllipticCurve. Using SECP256R1");
            curve = new EllipticCurveSECP256R1();
        }
        BigInteger privateKey = message.getComputations().getPrivateKey().getValue();
        Point publicKey = curve.mult(privateKey, curve.getBasePoint());
        message.getComputations().setPublicKeyX(publicKey.getFieldX().getData());
        message.getComputations().setPublicKeyY(publicKey.getFieldY().getData());
        publicKey =
                curve.getPoint(
                        message.getComputations().getPublicKeyX().getValue(),
                        message.getComputations().getPublicKeyY().getValue());
        byte[] publicKeyBytes =
                PointFormatter.formatToByteArray(
                        usedGroup.getGroupParameters(), publicKey, ECPointFormat.UNCOMPRESSED.getFormat());
        message.setPublicKey(publicKeyBytes);
        message.setPublicKeyLength(message.getPublicKey().getValue().length);

        prepareAfterParse(message, chooser, usedGroup);

        ECDHClientKeyExchangeSerializer serializer = message.getSerializer(state.getTlsContext(getConnectionAlias()));
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        message.setCompleteResultingMessage(serializer.serialize());

        container.add(message);
        setExecuted(true);
    }

    private void prepareAfterParse(ECDHClientKeyExchangeMessage message, Chooser chooser, NamedGroup usedGroup) {
        message.prepareComputations();
        byte[] random = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        message.getComputations().setClientServerRandom(random);
        LOGGER.debug("PMS used Group: {}", usedGroup.name());
        Point publicKey;
        CyclicGroup<?> group = usedGroup.getGroupParameters().getGroup();
        if (chooser.getConnectionEndType() == ConnectionEndType.SERVER) {
            publicKey =
                    PointFormatter.formatFromByteArray(
                            usedGroup.getGroupParameters(), message.getPublicKey().getValue());
        } else {
            publicKey = chooser.getEcKeyExchangePeerPublicKey();
        }
        EllipticCurve curve;
        if (group instanceof EllipticCurve) {
            curve = (EllipticCurve) group;
        } else {
            LOGGER.warn("Selected group is not an EllipticCurve. Using SECP256R1");
            curve = new EllipticCurveSECP256R1();
        }

        byte[] premasterSecret =
                computePremasterSecret(message,
                        curve, publicKey, message.getComputations().getPrivateKey().getValue());
        message.getComputations().setPremasterSecret(premasterSecret);
    }

    protected byte[] computePremasterSecret(ECDHClientKeyExchangeMessage message,
            EllipticCurve curve, Point publicKey, BigInteger privateKey) {
        if (curve instanceof RFC7748Curve) {
            RFC7748Curve rfc7748Curve = (RFC7748Curve) curve;
            return rfc7748Curve.computeSharedSecretFromDecodedPoint(
                    message.getComputations().getPrivateKey().getValue(), publicKey);
        } else {
            Point sharedPoint = curve.mult(privateKey, publicKey);
            if (sharedPoint == null) {
                LOGGER.warn("Computed null shared point. Using basepoint instead");
                sharedPoint = curve.getBasePoint();
            }
            if (sharedPoint.isAtInfinity()) {
                LOGGER.warn(
                        "Computed shared secrets as point in infinity. Using new byte[1] as PMS");
                return new byte[1];
            }
            int elementLength =
                    ArrayConverter.bigIntegerToByteArray(sharedPoint.getFieldX().getModulus())
                            .length;
            return ArrayConverter.bigIntegerToNullPaddedByteArray(
                    sharedPoint.getFieldX().getData(), elementLength);
        }
    }


    @Override
    public void reset() { }

    @Override
    public boolean executedAsPlanned() {
        return true;
    }


}

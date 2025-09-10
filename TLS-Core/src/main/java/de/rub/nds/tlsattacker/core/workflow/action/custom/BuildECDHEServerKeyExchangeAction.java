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
import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.TlsSignatureUtil;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.protocol.serializer.ECDHEServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.ServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildServerKeyExchangeAction")
public class BuildECDHEServerKeyExchangeAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;
    @XmlTransient private List<HandshakeMessageType> type_container = null;
    @XmlTransient private List<EllipticCurveType> curve_type_container = null;
    @XmlTransient private List<NamedGroup> group_container = null;
    @XmlTransient private List<byte[]> ec_private_container = null;

    public BuildECDHEServerKeyExchangeAction() {
        super();
    }

    public BuildECDHEServerKeyExchangeAction(String alias) {
        super(alias);
    }

    public BuildECDHEServerKeyExchangeAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildECDHEServerKeyExchangeAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildECDHEServerKeyExchangeAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setHandshakeType(List<HandshakeMessageType> type_container) {
        this.type_container = type_container;
    }

    public void setCurveType(List<EllipticCurveType> curve_type_container) {
        this.curve_type_container = curve_type_container;
    }

    public void setNamedCurve(List<NamedGroup> group_container) {
        this.group_container = group_container;
    }

    public void setECPrivateKey(List<byte[]> ec_private_container) {
        this.ec_private_container = ec_private_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        ECDHEServerKeyExchangeMessage message = new ECDHEServerKeyExchangeMessage();
        message.prepareKeyExchangeComputations();
        message.getKeyExchangeComputations().setEcPointFormat(ECPointFormat.UNCOMPRESSED.getValue());

        if(type_container != null) {
            message.setType(type_container.get(0).getValue());
        } else {
            message.setType(HandshakeMessageType.SERVER_KEY_EXCHANGE.getValue());
        }
        if (curve_type_container != null) {
            message.setCurveType(curve_type_container.get(0).getValue());
        }
        if (group_container != null) {
            message.getKeyExchangeComputations().setNamedGroup(group_container.get(0).getValue());
            message.setNamedGroup(group_container.get(0).getValue());
        }
        if (ec_private_container != null) {
            BigInteger privateKey = new BigInteger(1, ec_private_container.get(0));
            message.getKeyExchangeComputations().setPrivateKey(privateKey);
        }
        message.setSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.ECDSA_SHA256.getByteValue());
        setPublicKey(message);

        Chooser chooser = state.getTlsContext(getConnectionAlias()).getChooser();
        message.getKeyExchangeComputations()
                .setClientServerRandom(
                        ArrayConverter.concatenate(
                                chooser.getClientRandom(), chooser.getServerRandom()));

        byte[] signature = generateSignature(message, generateSignatureContents(message), chooser);
        message.setSignature(signature);
        message.setSignatureLength(message.getSignature().getValue().length);

        ECDHEServerKeyExchangeSerializer serializer =  message.getSerializer(state.getTlsContext(getConnectionAlias()));
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        message.setCompleteResultingMessage(serializer.serialize());

        container.add(message);
        setExecuted(true);
    }

    void setPublicKey(ECDHEServerKeyExchangeMessage message){
        NamedGroup namedGroup = NamedGroup.getNamedGroup(message.getNamedGroup().getValue());
        ECPointFormat pointFormat = ECPointFormat.getECPointFormat(message.getKeyExchangeComputations().getEcPointFormat().getValue());

        EllipticCurve curve = (EllipticCurve) namedGroup.getGroupParameters().getGroup();

        Point publicKey =
                curve.mult(
                        message.getKeyExchangeComputations().getPrivateKey().getValue(),
                        curve.getBasePoint());
        byte[] publicKeyBytes =
                PointFormatter.formatToByteArray(
                        (namedGroup.getGroupParameters()), publicKey, pointFormat.getFormat());
        message.setPublicKey(publicKeyBytes);
        message.setPublicKeyLength(message.getPublicKey().getValue().length);
    }

    private byte[] generateSignatureContents(ECDHEServerKeyExchangeMessage message){
        ByteArrayOutputStream ecParams = new ByteArrayOutputStream();
        try {
            ecParams.write(message.getKeyExchangeComputations().getEcPointFormat().getValue());
            ecParams.write(message.getNamedGroup().getValue());
            ecParams.write(message.getPublicKeyLength().getValue());
            ecParams.write(message.getPublicKey().getValue());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return ArrayConverter.concatenate(
                message.getKeyExchangeComputations().getClientServerRandom().getValue(),
                ecParams.toByteArray());
    }

    private byte[] generateSignature(ECDHEServerKeyExchangeMessage message, byte[] toBeHashedAndSigned, Chooser chooser){
        TlsSignatureUtil util = new TlsSignatureUtil();
        util.computeSignature(
                chooser,
                SignatureAndHashAlgorithm.ECDSA_SHA256,
                toBeHashedAndSigned,
                message.getSignatureComputations(SignatureAndHashAlgorithm.ECDSA_SHA256.getSignatureAlgorithm()));
        return message.getSignatureComputations(SignatureAndHashAlgorithm.ECDSA_SHA256.getSignatureAlgorithm())
                .getSignatureBytes()
                .getValue();
    }

    @Override
    public void reset() { }

    @Override
    public boolean executedAsPlanned() {
        return true;
    }


}

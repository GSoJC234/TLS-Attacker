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
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.RSAClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.RSAClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.serializer.RecordSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.x509attacker.x509.model.publickey.PublicKeyContent;
import de.rub.nds.x509attacker.x509.model.publickey.X509RsaPublicKey;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.math.BigInteger;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "ReEncryptRSAClientKeyExchange")
public class ReEncryptRSAClientKeyExchange extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;
    @XmlTransient private List<Record> record_container = null;

    @XmlTransient private List<byte[]> preMasterSecret_container = null;
    @XmlTransient private List<PublicKeyContent> encryptKey_container = null;

    public ReEncryptRSAClientKeyExchange() {
        super();
    }

    public ReEncryptRSAClientKeyExchange(String alias) {
        super(alias);
    }

    public ReEncryptRSAClientKeyExchange(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public ReEncryptRSAClientKeyExchange(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public ReEncryptRSAClientKeyExchange(
            String alias, List<ProtocolMessage> container, List<Record> record_container) {
        super(alias);
        this.container = container;
        this.record_container = record_container;
    }

    public void setEncryptKey_container(List<PublicKeyContent> encryptKey_container) {
        this.encryptKey_container = encryptKey_container;
    }

    public void setPreMasterSecret_container(List<byte[]> preMasterSecret_container) {
        this.preMasterSecret_container = preMasterSecret_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext context = state.getTlsContext(getConnectionAlias());

        RSAClientKeyExchangeMessage message = (RSAClientKeyExchangeMessage) container.get(0);
        message.setShouldPrepareDefault(false);

        X509RsaPublicKey encryptKey = (X509RsaPublicKey) encryptKey_container.get(0);
        message.getComputations().setModulus(encryptKey.getModulus().getValue());
        message.getComputations().setPublicExponent(encryptKey.getPublicExponent().getValue());
        int ceiledModulusByteLength =
                (int)
                        Math.ceil(
                                (double)
                                                new BigInteger(
                                                                encryptKey
                                                                        .getModulus()
                                                                        .getValue()
                                                                        .getByteArray())
                                                        .bitLength()
                                        / Bits.IN_A_BYTE);
        int randomByteLength = ceiledModulusByteLength - HandshakeByteLength.PREMASTER_SECRET - 3;
        // If the key is really really short it might be impossible to add padding;
        byte[] padding;
        if (randomByteLength > 0) {
            padding = new byte[randomByteLength];
            state.getTlsContext(getConnectionAlias()).getRandom().nextBytes(padding);
            ArrayConverter.makeArrayNonZero(padding);
        } else {
            padding = new byte[0];
        }
        message.getComputations().setPadding(padding);

        byte[] preMasterSecret = preMasterSecret_container.get(0);
        message.getComputations().setPremasterSecret(preMasterSecret);
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
        byte[] encrypted =
                ArrayConverter.bigIntegerToByteArray(biEncrypted, ceiledModulusByteLength, true);
        message.setPublicKey(encrypted);
        message.setPublicKeyLength(message.getPublicKey().getValue().length);

        RSAClientKeyExchangeSerializer serializer = message.getSerializer(context);
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        message.setCompleteResultingMessage(serializer.serialize());

        state.getContext(getConnectionAlias())
                .setTalkingConnectionEndType(
                        state.getContext(getConnectionAlias())
                                .getConnection()
                                .getLocalConnectionEndType());
        RSAClientKeyExchangeHandler handler =
                message.getHandler(state.getTlsContext(getConnectionAlias()));
        handler.adjustContext(message);
        handler.adjustContextAfterSerialize(message);
        message.setAdjustContext(false);

        Record record = record_container.get(0);
        record.setProtocolMessageBytes(message.getCompleteResultingMessage());
        record.setCleanProtocolMessageBytes(message.getCompleteResultingMessage());
        record.setLength(record.getProtocolMessageBytes().getValue().length);

        RecordSerializer serializer2 = new RecordSerializer(record);
        record.setCompleteRecordBytes(serializer2.serialize());

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

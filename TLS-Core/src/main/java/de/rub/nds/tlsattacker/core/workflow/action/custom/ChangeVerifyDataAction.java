/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.FinishedSerializer;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.serializer.RecordSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

@XmlRootElement(name = "ChangeVerifyDataAction")
public class ChangeVerifyDataAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;
    @XmlTransient private List<Record> record_container = null;
    @XmlTransient private List<byte[]> masterSecret_container = null;

    public ChangeVerifyDataAction() {
        super();
    }

    public ChangeVerifyDataAction(String alias) {
        super(alias);
    }

    public ChangeVerifyDataAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public ChangeVerifyDataAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public ChangeVerifyDataAction(
            String alias, List<ProtocolMessage> container, List<Record> record_container) {
        super(alias);
        this.container = container;
        this.record_container = record_container;
    }

    public void setMasterSecret_container(List<byte[]> masterSecret_container) {
        this.masterSecret_container = masterSecret_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());

        FinishedMessage message = (FinishedMessage) container.get(0);
        message.setShouldPrepareDefault(false);

        Context context = state.getContext(getConnectionAlias());
        context.setTalkingConnectionEndType(context.getConnection().getLocalConnectionEndType());
        try {
            message.setVerifyData(computeVerifyData(state));
        } catch (CryptoException e) {
            throw new ActionExecutionException("Could not compute verify data.", e);
        }

        FinishedSerializer serializer = new FinishedSerializer(message);
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        message.setCompleteResultingMessage(serializer.serialize());

        state.getContext(getConnectionAlias())
                .setTalkingConnectionEndType(
                        state.getContext(getConnectionAlias())
                                .getConnection()
                                .getLocalConnectionEndType());
        // HandshakeMessageHandler handler =
        //        message.getHandler(state.getTlsContext(getConnectionAlias()));
        // handler.adjustContext(message);
        // message.setAdjustContext(false);

        Record record = record_container.get(0);
        record.setProtocolMessageBytes(message.getCompleteResultingMessage());
        record.setCleanProtocolMessageBytes(message.getCompleteResultingMessage());
        record.setLength(record.getProtocolMessageBytes().getValue().length);

        RecordSerializer serializer2 = new RecordSerializer(record);
        record.setCompleteRecordBytes(serializer2.serialize());

        setExecuted(true);
    }

    private byte[] computeVerifyData(State state) throws CryptoException {
        Chooser chooser = state.getTlsContext(getConnectionAlias()).getChooser();
        if (chooser.getSelectedProtocolVersion().isTLS13()) {
            try {
                HKDFAlgorithm hkdfAlgorithm =
                        AlgorithmResolver.getHKDFAlgorithm(chooser.getSelectedCipherSuite());
                String javaMacName = hkdfAlgorithm.getMacAlgorithm().getJavaName();
                int macLength = Mac.getInstance(javaMacName).getMacLength();
                LOGGER.debug("Connection End: " + chooser.getTalkingConnectionEnd());
                byte[] trafficSecret;
                if (chooser.getTalkingConnectionEnd() == ConnectionEndType.SERVER) {
                    trafficSecret = chooser.getServerHandshakeTrafficSecret();
                } else {
                    trafficSecret = chooser.getClientHandshakeTrafficSecret();
                }
                byte[] finishedKey =
                        HKDFunction.expandLabel(
                                hkdfAlgorithm,
                                trafficSecret,
                                HKDFunction.FINISHED,
                                new byte[0],
                                macLength);
                LOGGER.info("Finished key: {}", Arrays.toString(finishedKey));
                SecretKeySpec keySpec = new SecretKeySpec(finishedKey, javaMacName);
                byte[] result;
                Mac mac = Mac.getInstance(javaMacName);
                mac.init(keySpec);
                mac.update(
                        chooser.getContext()
                                .getTlsContext()
                                .getDigest()
                                .digest(
                                        chooser.getSelectedProtocolVersion(),
                                        chooser.getSelectedCipherSuite()));
                result = mac.doFinal();
                return result;
            } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
                throw new CryptoException(ex);
            }
        } else {
            LOGGER.debug("Calculating VerifyData:");
            PRFAlgorithm prfAlgorithm = chooser.getPRFAlgorithm();
            LOGGER.debug("Using PRF:" + prfAlgorithm.name());
            byte[] masterSecret = masterSecret_container.get(0);
            LOGGER.debug("Using MasterSecret: {}", masterSecret);
            byte[] handshakeMessageHash =
                    chooser.getContext()
                            .getTlsContext()
                            .getDigest()
                            .digest(
                                    chooser.getSelectedProtocolVersion(),
                                    chooser.getSelectedCipherSuite());
            LOGGER.debug("Using HandshakeMessage Hash: {}", handshakeMessageHash);

            String label;
            if (chooser.getTalkingConnectionEnd() == ConnectionEndType.SERVER) {
                // TODO put this in separate config option
                label = PseudoRandomFunction.SERVER_FINISHED_LABEL;
            } else {
                label = PseudoRandomFunction.CLIENT_FINISHED_LABEL;
            }
            byte[] res =
                    PseudoRandomFunction.compute(
                            prfAlgorithm,
                            masterSecret,
                            label,
                            handshakeMessageHash,
                            HandshakeByteLength.VERIFY_DATA);
            return res;
        }
    }

    @Override
    public void reset() {}

    @Override
    public boolean executedAsPlanned() {
        return false;
    }
}

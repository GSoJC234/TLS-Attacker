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
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.FinishedHandler;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.FinishedSerializer;
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
import java.util.List;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

@XmlRootElement(name = "BuildFinishedAction")
public class BuildFinishedAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;

    @XmlTransient private List<HandshakeMessageType> message_type_container = null;
    @XmlTransient private List<Boolean> message_length_container = null;
    @XmlTransient private List<byte[]> verify_data_container = null;

    public BuildFinishedAction() {
        super();
    }

    public BuildFinishedAction(String alias) {
        super(alias);
    }

    public BuildFinishedAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildFinishedAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildFinishedAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setHandshakeMessageType(List<HandshakeMessageType> message_type_container) {
        this.message_type_container = message_type_container;
    }

    public void setMessageLength(List<Boolean> message_length_container) {
        this.message_length_container = message_length_container;
    }

    public void setVerifyData(List<byte[]> verify_data_container) {
        this.verify_data_container = verify_data_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        FinishedMessage message = new FinishedMessage();
        message.setShouldPrepareDefault(false);
        message.setType(message_type_container.get(0).getValue());
        if (verify_data_container != null) {
            message.setVerifyData(verify_data_container.get(0));
        } else {
            try {
                message.setVerifyData(computeVerifyData(state));
            } catch (CryptoException e) {
                throw new ActionExecutionException("Could not compute verify data.", e);
            }
        }

        FinishedSerializer serializer = new FinishedSerializer(message);
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        if (!message_length_container.get(0)) {
            throw new ActionExecutionException("Unsupported modified message length");
        }
        message.setCompleteResultingMessage(serializer.serialize());

        Context context = state.getContext(getConnectionAlias());
        context.setTalkingConnectionEndType(context.getConnection().getLocalConnectionEndType());

        FinishedHandler handler = new FinishedHandler(state.getTlsContext(getConnectionAlias()));
        handler.updateDigest(message, true);
        handler.adjustContext(message);
        message.setAdjustContext(false);

        container.add(message);
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
                LOGGER.debug("Finished key: {}", finishedKey);
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
            byte[] masterSecret = chooser.getMasterSecret();
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
}

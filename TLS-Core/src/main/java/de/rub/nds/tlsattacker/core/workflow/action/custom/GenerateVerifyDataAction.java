/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
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

@XmlRootElement(name = "GenerateVerifyDataAction")
public class GenerateVerifyDataAction extends ConnectionBoundAction {

    @XmlTransient
    private List<byte[]> verify_data_container = null;

    public GenerateVerifyDataAction() {
        super();
    }

    public GenerateVerifyDataAction(String alias) {
        super(alias);
    }

    public GenerateVerifyDataAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public GenerateVerifyDataAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public GenerateVerifyDataAction(String alias, List<byte[]> container) {
        super(alias);
        this.verify_data_container = container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        Context context = state.getContext(getConnectionAlias());
        context.setTalkingConnectionEndType(
                context.getConnection().getLocalConnectionEndType());
        try {
            byte[] verifyData = computeVerifyData(state);
            this.verify_data_container.add(verifyData);
        } catch (CryptoException e) {
            throw new RuntimeException("Could not compute verify data.", e);
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

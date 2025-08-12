/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.exception.PreparationException;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKBinder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKIdentity;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.protocol.serializer.ClientHelloSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PSKBinderSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PSKIdentitySerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PreSharedKeyExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

@XmlRootElement(name = "AddPreSharedKeyAction")
public class AddPreSharedKeyAction extends AddExtensionAction<SessionTicket> {
    public AddPreSharedKeyAction() {
        super();
    }

    public AddPreSharedKeyAction(String alias) {
        super(alias);
    }

    public AddPreSharedKeyAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
    }

    public AddPreSharedKeyAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public AddPreSharedKeyAction(String alias, List<ProtocolMessage> container) {
        super(alias, container);
    }

    private void calculateActualBinder(PreSharedKeyExtensionMessage message, Chooser chooser){
        LOGGER.debug("Preparing binder values to replace dummy bytes");
        ClientHelloSerializer clientHelloSerializer =
                new ClientHelloSerializer((ClientHelloMessage) container.get(0), ProtocolVersion.TLS13);
        byte[] clientHelloBytes = clientHelloSerializer.serialize();
        byte[] relevantBytes = getRelevantBytes(clientHelloBytes, message);
        calculateBinders(relevantBytes, message, chooser);
        prepareBinderListBytes(message);
    }

    private void prepareBinderListBytes(PreSharedKeyExtensionMessage msg) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        if (msg.getBinders() != null) {
            for (PSKBinder pskBinder : msg.getBinders()) {
                PSKBinderSerializer serializer = new PSKBinderSerializer(pskBinder);
                try {
                    outputStream.write(serializer.serialize());
                } catch (IOException ex) {
                    throw new PreparationException("Could not write byte[] from PSKIdentity", ex);
                }
            }
        } else {
            LOGGER.debug("No PSK available, setting empty binder list");
        }
        msg.setBinderListBytes(outputStream.toByteArray());
        msg.setBinderListLength(msg.getBinderListBytes().getValue().length);
    }

    private void calculateBinders(byte[] relevantBytes, PreSharedKeyExtensionMessage msg, Chooser chooser) {
        TlsContext tlsContext = chooser.getContext().getTlsContext();
        List<PskSet> pskSets = chooser.getPskSets();
        if (msg.getBinders() != null) {
            LOGGER.debug("Calculating Binders");
            for (int x = 0; x < msg.getBinders().size(); x++) {
                try {
                    if (pskSets.size() > x) {
                        HKDFAlgorithm hkdfAlgorithm =
                                AlgorithmResolver.getHKDFAlgorithm(pskSets.get(x).getCipherSuite());
                        Mac mac = Mac.getInstance(hkdfAlgorithm.getMacAlgorithm().getJavaName());
                        DigestAlgorithm digestAlgo =
                                AlgorithmResolver.getDigestAlgorithm(
                                        ProtocolVersion.TLS13, pskSets.get(x).getCipherSuite());

                        byte[] psk = pskSets.get(x).getPreSharedKey();
                        byte[] earlySecret = HKDFunction.extract(hkdfAlgorithm, new byte[0], psk);
                        byte[] binderKey =
                                HKDFunction.deriveSecret(
                                        hkdfAlgorithm,
                                        digestAlgo.getJavaName(),
                                        earlySecret,
                                        HKDFunction.BINDER_KEY_RES,
                                        ArrayConverter.hexStringToByteArray(""));
                        byte[] binderFinKey =
                                HKDFunction.expandLabel(
                                        hkdfAlgorithm,
                                        binderKey,
                                        HKDFunction.FINISHED,
                                        new byte[0],
                                        mac.getMacLength());

                        tlsContext.getDigest().setRawBytes(relevantBytes);
                        SecretKeySpec keySpec = new SecretKeySpec(binderFinKey, mac.getAlgorithm());
                        mac.init(keySpec);
                        mac.update(
                                tlsContext
                                        .getDigest()
                                        .digest(
                                                ProtocolVersion.TLS13,
                                                pskSets.get(x).getCipherSuite()));
                        byte[] binderVal = mac.doFinal();
                        tlsContext.getDigest().setRawBytes(new byte[0]);

                        LOGGER.debug("Using PSK: {}", psk);
                        LOGGER.debug("Calculated Binder: {}", binderVal);

                        msg.getBinders().get(x).setBinderEntry(binderVal);
                        // First entry = PSK for early Data
                        if (x == 0) {
                            tlsContext.setEarlyDataPsk(psk);
                        }
                    } else {
                        LOGGER.warn("Skipping BinderCalculation as Config has not enough PSK sets");
                    }
                } catch (NoSuchAlgorithmException | InvalidKeyException | CryptoException ex) {
                    throw new PreparationException("Could not calculate Binders", ex);
                }
            }
        } else {
            LOGGER.debug("No PSK dummy binders set, skipping binder computation");
        }
    }

    private byte[] getRelevantBytes(byte[] clientHelloBytes, PreSharedKeyExtensionMessage message) {
        int remainingBytes = clientHelloBytes.length - ExtensionByteLength.PSK_BINDER_LIST_LENGTH;
        if (message.getBinders() != null) {
            for (PSKBinder pskBinder : message.getBinders()) {
                remainingBytes =
                        remainingBytes
                                - ExtensionByteLength.PSK_BINDER_LENGTH
                                - pskBinder.getBinderEntryLength().getValue();
            }
        }
        if (remainingBytes > 0) {
            byte[] relevantBytes = new byte[remainingBytes];

            System.arraycopy(
                    clientHelloBytes,
                    0,
                    relevantBytes,
                    0,
                    Math.min(remainingBytes, clientHelloBytes.length));

            LOGGER.debug("Relevant Bytes: {}", relevantBytes);
            return relevantBytes;
        } else {
            // This can happen if the client hello degenerates
            return new byte[0];
        }
    }

    @Override
    protected ExtensionMessage generateExtensionMessages(ConnectionEndType endType, State state) {
        PreSharedKeyExtensionMessage message = new PreSharedKeyExtensionMessage();
        message.setExtensionType(ExtensionType.PRE_SHARED_KEY.getValue());

        List<SessionTicket> sessionTickets = extension_container;
        if(endType == ConnectionEndType.CLIENT) {
            List<PSKIdentity> identities = new ArrayList<PSKIdentity>();
            List<PSKBinder> binders = new ArrayList<PSKBinder>();

            for(SessionTicket t : sessionTickets) {
                PSKIdentity id = new PSKIdentity();
                id.setIdentity(t.getIdentity().getValue());
                id.setIdentityLength(t.getIdentityLength().getValue());

                id.setObfuscatedTicketAge(t.getTicketAgeAdd().getValue());
                identities.add(id);

                PSKBinder binder = new PSKBinder();
                binder.setBinderEntryLength(0);
                binder.setBinderEntry(new byte[0]);
                binders.add(binder);
            }

            message.setIdentities(identities);
            message.setBinders(binders);

            // identity_list 직렬화/길이
            try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                for (PSKIdentity id : identities) {
                    out.write(new PSKIdentitySerializer(id).serialize());
                }
                message.setIdentityListBytes(out.toByteArray());
            } catch (IOException e) {
                throw new RuntimeException("Failed to serialize PSK identities", e);
            }
            message.setIdentityListLength(message.getIdentityListBytes().getValue().length);

            // binder_list 직렬화/길이 (현재는 더미)
            try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                for (PSKBinder b : binders) {
                    out.write(new PSKBinderSerializer(b).serialize());
                }
                message.setBinderListBytes(out.toByteArray());
            } catch (IOException e) {
                throw new RuntimeException("Failed to serialize PSK binders", e);
            }
            message.setBinderListLength(message.getBinderListBytes().getValue().length);

        } else {
            SessionTicket ticket = sessionTickets.get(0);
            message.setSelectedIdentity(0);
        }

        PreSharedKeyExtensionSerializer serializer =
                new PreSharedKeyExtensionSerializer(message, endType);
        message.setExtensionContent(serializer.serializeExtensionContent());
        message.setExtensionLength(message.getExtensionContent().getValue().length);
        message.setExtensionBytes(serializer.serialize());

        if(endType == ConnectionEndType.CLIENT) {
            calculateActualBinder(message, state.getContext(getConnectionAlias()).getChooser());
        }

        return message;
    }

}

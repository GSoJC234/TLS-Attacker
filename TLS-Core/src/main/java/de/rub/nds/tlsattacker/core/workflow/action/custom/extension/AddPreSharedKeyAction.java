/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom.extension;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToHexString;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.exception.PreparationException;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKBinder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKIdentity;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.protocol.serializer.ClientHelloSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
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

    private void prepareBinderListBytes(PreSharedKeyExtensionMessage msg) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        if (msg.getBinders() != null) {
            for (PSKBinder pskBinder : msg.getBinders()) {
                PSKBinderSerializer serializer = new PSKBinderSerializer(pskBinder);
                try {
                    outputStream.write(serializer.serialize());
                } catch (IOException ex) {
                    throw new PreparationException("Could not write byte[] from PSKBinder", ex);
                }
            }
        } else {
            LOGGER.debug("No PSK available, setting empty binder list");
        }
        msg.setBinderListBytes(outputStream.toByteArray());
        msg.setBinderListLength(msg.getBinderListBytes().getValue().length);
    }

    /**
     * Compute binders given the full ClientHello bytes that already contain the PSK extension
     * with ZERO-filled binders of the correct length.
     */
    private void calculateBinders(byte[] clientHelloWithZeroBinders,
                                  PreSharedKeyExtensionMessage msg,
                                  Chooser chooser) {
        TlsContext tlsContext = chooser.getContext().getTlsContext();
        List<PskSet> pskSets = chooser.getPskSets();

        if (msg.getBinders() == null) {
            LOGGER.debug("No PSK dummy binders set, skipping binder computation");
            return;
        }

        LOGGER.debug("Calculating Binders over zero-filled ClientHello (len={})",
                clientHelloWithZeroBinders != null ? clientHelloWithZeroBinders.length : 0);

        for (int x = 0; x < msg.getBinders().size(); x++) {
            try {
                if (pskSets == null || pskSets.size() <= x) {
                    throw new PreparationException("No PskSet for binder index " + x);
                }

                CipherSuite suiteForPsk = pskSets.get(x).getCipherSuite();
                if (suiteForPsk == null) {
                    suiteForPsk = chooser.getSelectedCipherSuite();
                }
                HKDFAlgorithm hkdfAlgorithm = AlgorithmResolver.getHKDFAlgorithm(suiteForPsk);
                DigestAlgorithm digestAlgo =
                        AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS13, suiteForPsk);

                Mac mac = Mac.getInstance(hkdfAlgorithm.getMacAlgorithm().getJavaName());
                int macLen = mac.getMacLength();

                byte[] psk = pskSets.get(x).getPreSharedKey(); // should already be resumption_psk
                if (psk == null) {
                    throw new PreparationException("PSK bytes missing in PskSet[" + x + "]");
                }

                // Early Secret = HKDF-Extract(0, PSK)
                byte[] earlySecret = HKDFunction.extract(hkdfAlgorithm, new byte[0], psk);

                // binder_key = Derive-Secret(early, "res binder", "")
                byte[] binderKey =
                        HKDFunction.deriveSecret(
                                hkdfAlgorithm,
                                digestAlgo.getJavaName(),
                                earlySecret,
                                HKDFunction.BINDER_KEY_RES,
                                ArrayConverter.hexStringToByteArray(""));

                // finished_key(binder) = HKDF-Expand-Label(binder_key, "finished", "", macLen)
                byte[] binderFinKey =
                        HKDFunction.expandLabel(
                                hkdfAlgorithm, binderKey, HKDFunction.FINISHED, new byte[0], macLen);

                // Transcript-Hash over ClientHello that includes PSK extension with zeroed binders
                tlsContext.getDigest().setRawBytes(clientHelloWithZeroBinders);
                SecretKeySpec keySpec = new SecretKeySpec(binderFinKey, mac.getAlgorithm());
                mac.init(keySpec);
                mac.update(tlsContext.getDigest().digest(ProtocolVersion.TLS13, suiteForPsk));
                byte[] binderVal = mac.doFinal();
                tlsContext.getDigest().setRawBytes(new byte[0]);

                LOGGER.debug("Using PSK[{}] (len={}): {}", x, psk.length, bytesToHexString(psk));
                LOGGER.debug("Calculated Binder[{}] (len={}): {}", x, binderVal.length, bytesToHexString(binderVal));

                // Set binder value and length
                PSKBinder binder = msg.getBinders().get(x);
                binder.setBinderEntry(binderVal);
                binder.setBinderEntryLength(binderVal.length);

                // First entry = PSK for early data (if needed downstream)
                if (x == 0) {
                    tlsContext.setEarlyDataPsk(psk);
                }

            } catch (NoSuchAlgorithmException | InvalidKeyException | CryptoException ex) {
                throw new PreparationException("Could not calculate Binders", ex);
            }
        }
    }

    @Override
    protected ExtensionMessage generateExtensionMessages(ConnectionEndType endType, State state) {
        PreSharedKeyExtensionMessage message = new PreSharedKeyExtensionMessage();
        message.setExtensionType(ExtensionType.PRE_SHARED_KEY.getValue());

        List<SessionTicket> sessionTickets = extension_container;

        if (endType == ConnectionEndType.CLIENT) {
            Chooser chooser = state.getContext(getConnectionAlias()).getChooser();
            List<PskSet> pskSets = chooser.getPskSets();

            List<PSKIdentity> identities = new ArrayList<>();
            List<PSKBinder> binders = new ArrayList<>();

            for (SessionTicket t : sessionTickets) {
                // Identity
                PSKIdentity id = new PSKIdentity();
                id.setIdentity(t.getIdentity().getValue());
                if (t.getIdentity() != null && t.getIdentity().getValue() != null) {
                    id.setIdentityLength(t.getIdentity().getValue().length);
                } else {
                    id.setIdentityLength(0);
                }

                // NOTE: Real obfuscated age is (age_ms + ticket_age_add) mod 2^32.
                // Here we keep prior behavior as provided by the caller.
                id.setObfuscatedTicketAge(t.getTicketAgeAdd().getValue());
                identities.add(id);

                // Binder dummy (ZERO-filled) with correct hash length
                PSKBinder binder = new PSKBinder();
                int idx = binders.size();

                CipherSuite suiteForPsk =
                        (pskSets != null && idx < pskSets.size() && pskSets.get(idx).getCipherSuite() != null)
                                ? pskSets.get(idx).getCipherSuite()
                                : chooser.getSelectedCipherSuite();

                HKDFAlgorithm hkdfAlg = AlgorithmResolver.getHKDFAlgorithm(suiteForPsk);
                int hashLen;
                try {
                    Mac hmac = Mac.getInstance(hkdfAlg.getMacAlgorithm().getJavaName()); // e.g., HmacSHA256
                    hashLen = hmac.getMacLength(); // 32 for SHA-256, 48 for SHA-384, ...
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException("No Mac for " + hkdfAlg.getMacAlgorithm().getJavaName(), e);
                }

                binder.setBinderEntryLength(hashLen);
                binder.setBinderEntry(new byte[hashLen]); // zero-filled placeholder
                binders.add(binder);
            }

            message.setIdentities(identities);
            message.setBinders(binders);

            // identity_list bytes/length
            try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                for (PSKIdentity id : identities) {
                    out.write(new PSKIdentitySerializer(id).serialize());
                }
                message.setIdentityListBytes(out.toByteArray());
            } catch (IOException e) {
                throw new RuntimeException("Failed to serialize PSK identities", e);
            }
            message.setIdentityListLength(message.getIdentityListBytes().getValue().length);

            // binder_list bytes/length (ZERO-filled dummies for now)
            try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                for (PSKBinder b : binders) {
                    out.write(new PSKBinderSerializer(b).serialize());
                }
                message.setBinderListBytes(out.toByteArray());
            } catch (IOException e) {
                throw new RuntimeException("Failed to serialize PSK binders", e);
            }
            message.setBinderListLength(message.getBinderListBytes().getValue().length);
        } else { // Server side: only selected_identity is relevant
            SessionTicket ticket = sessionTickets.get(0);
            message.setSelectedIdentity(0);
        }

        PreSharedKeyExtensionSerializer serializer =
                new PreSharedKeyExtensionSerializer(message, endType);
        message.setExtensionContent(serializer.serializeExtensionContent());
        message.setExtensionLength(message.getExtensionContent().getValue().length);
        message.setExtensionBytes(serializer.serialize());
        return message;
    }

    /**
     * Override to ensure the binder input equals the full ClientHello that already
     * includes the PSK extension with ZERO-filled binders.
     *
     * Steps:
     *  1) Build PSK extension (with zero binders) via generateExtensionMessages().
     *  2) Append PSK extension to ClientHello (as LAST extension) and serialize ClientHello.
     *  3) Compute binders over that serialized ClientHello.
     *  4) Replace binders and re-serialize extension + ClientHello.
     */
    @Override
    public void execute(State state) throws ActionExecutionException {
        try {
            HandshakeMessage message = (HandshakeMessage) container.get(0);
            ConnectionEndType endType =
                    state.getContext(getConnectionAlias()).getConnection().getLocalConnectionEndType();

            // 1) PSK 확장(제로 바인더 상태) 생성
            PreSharedKeyExtensionMessage pskExt =
                    (PreSharedKeyExtensionMessage) generateExtensionMessages(endType, state);

            // 2) 확장 리스트의 마지막에 추가 (pre_shared_key는 반드시 마지막)
            if (message.getExtensions() == null) {
                List<ExtensionMessage> messageList = new ArrayList<>();
                messageList.add(pskExt);
                message.setExtensions(messageList);
            } else {
                message.getExtensions().add(pskExt);
            }
            // ✅ 확장 블록만 갱신 (핸드셰이크 전체 직렬화는 아직 하지 않음)
            message.setExtensionBytes(extensionMessageBytes(message.getExtensions()));
            message.setExtensionsLength(message.getExtensionBytes().getValue().length);

            // 3) 바인더 입력용 ClientHello 바이트를 "직접" 뽑는다 (메시지에 반영 X)
            ClientHelloSerializer chSerForHash =
                    new ClientHelloSerializer((ClientHelloMessage) message, ProtocolVersion.TLS13);
            byte[] clientHelloWithZeroBinders = chSerForHash.serialize();

            // 4) 바인더 계산 및 값 반영
            Chooser chooser = state.getContext(getConnectionAlias()).getChooser();
            calculateBinders(clientHelloWithZeroBinders, pskExt, chooser);

            // 5) PSK 확장 재직렬화 (바인더 값 반영)
            prepareBinderListBytes(pskExt);
            PreSharedKeyExtensionSerializer extSer =
                    new PreSharedKeyExtensionSerializer(pskExt, endType);
            pskExt.setExtensionContent(extSer.serializeExtensionContent());
            pskExt.setExtensionLength(pskExt.getExtensionContent().getValue().length);
            pskExt.setExtensionBytes(extSer.serialize());

            // 6) 확장 블록 갱신
            message.setExtensionBytes(extensionMessageBytes(message.getExtensions()));
            message.setExtensionsLength(message.getExtensionBytes().getValue().length);

            // 7) 🔒 이제 딱 한 번만 핸드셰이크 전체 직렬화
            HandshakeMessageSerializer<?> serializer =
                    message.getSerializer(state.getTlsContext(getConnectionAlias()));
            message.setMessageContent(serializer.serializeHandshakeMessageContent());
            message.setLength(message.getMessageContent().getValue().length);
            message.setCompleteResultingMessage(serializer.serialize());

            // 마무리
            container.remove(0);
            container.add(message);
            setExecuted(true);

        } catch (RuntimeException e) {
            throw new ActionExecutionException("Failed to execute AddPreSharedKeyAction", e);
        }
    }
}

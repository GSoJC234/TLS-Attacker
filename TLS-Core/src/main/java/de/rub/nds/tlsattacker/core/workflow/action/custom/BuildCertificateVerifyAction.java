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
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.TlsSignatureUtil;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateVerifySerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.x509attacker.context.X509Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildCertificateVerifyAction")
public class BuildCertificateVerifyAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;
    @XmlTransient private List<HandshakeMessageType> type_container = null;
    @XmlTransient private List<byte[]> signature_container = null;
    @XmlTransient private List<byte[]> certificatePrivateKey_container = null;

    @XmlTransient
    private List<SignatureAndHashAlgorithm> signature_and_hash_algorithm_container = null;

    @XmlTransient
    private List<SignatureAndHashAlgorithm> signingSignatureAndHashAlgorithmContainer = null;

    public BuildCertificateVerifyAction() {
        super();
    }

    public BuildCertificateVerifyAction(String alias) {
        super(alias);
    }

    public BuildCertificateVerifyAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildCertificateVerifyAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildCertificateVerifyAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setSignature_and_hash_algorithm_container(
            List<SignatureAndHashAlgorithm> signature_and_hash_algorithm_container) {
        this.signature_and_hash_algorithm_container = signature_and_hash_algorithm_container;
    }

    /**
     * Selects the algorithm used to create the signature independently of the algorithm encoded
     * on the wire. If this setter is not used, the wire algorithm is also used for signing, which
     * preserves the historical behavior of this action.
     */
    public void setSigningSignatureAndHashAlgorithmContainer(
            List<SignatureAndHashAlgorithm> signingSignatureAndHashAlgorithmContainer) {
        this.signingSignatureAndHashAlgorithmContainer =
                signingSignatureAndHashAlgorithmContainer;
    }

    public void setCertificatePrivateKey(List<byte[]> certificatePrivateKey_container) {
        this.certificatePrivateKey_container = certificatePrivateKey_container;
    }

    public void setHandshakeType(List<HandshakeMessageType> type_container){
        this.type_container = type_container;
    }

    public void setSignature(List<byte[]> signature_container) {
        this.signature_container = signature_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        Context context = state.getContext(getConnectionAlias());

        BigInteger privateKey = new BigInteger(1, this.certificatePrivateKey_container.get(0));
        BigInteger rsaModulus =
                this.certificatePrivateKey_container.size() > 1
                        ? new BigInteger(1, this.certificatePrivateKey_container.get(1))
                        : null;
        SignatureAndHashAlgorithm wireAlgorithm;
        if(signature_and_hash_algorithm_container != null){
            wireAlgorithm = signature_and_hash_algorithm_container.get(0);
        } else {
            wireAlgorithm = context.getChooser().getSelectedSigHashAlgorithm();
        }
        SignatureAndHashAlgorithm signingAlgorithm = resolveSigningAlgorithm(wireAlgorithm);

        context.getTlsContext().setSelectedSignatureAndHashAlgorithm(wireAlgorithm);

        ConnectionEndType endType = context.getConnection().getLocalConnectionEndType();
        X509Context x509 = context.getTlsContext().getTalkingX509Context();
        setX509SubjectPrivateKey(
                x509, signingAlgorithm.getSignatureAlgorithm(), privateKey, rsaModulus);

        CertificateVerifyMessage message = new CertificateVerifyMessage();
        message.setShouldPrepareDefault(false);
        if(type_container != null) {
            message.setType(type_container.get(0).getValue());
        } else {
            message.setType(HandshakeMessageType.CERTIFICATE_VERIFY.getValue());
        }
        message.setSignatureHashAlgorithm(wireAlgorithm.getByteValue());

        if (signature_container != null) {
            message.setSignature(signature_container.get(0));
        } else {
            try {
                message.setSignature(createSignature(message, signingAlgorithm, state));
            } catch (CryptoException e) {
                throw new ActionExecutionException("Could not create signature", e);
            }
        }
        message.setSignatureLength(message.getSignature().getValue().length);

        CertificateVerifySerializer serializer =
                new CertificateVerifySerializer(
                        message, context.getTlsContext().getSelectedProtocolVersion());
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        message.setCompleteResultingMessage(serializer.serialize());

        container.add(message);
        System.out.println("CertificateVerify: " + message);
        setExecuted(true);
    }

    SignatureAndHashAlgorithm resolveSigningAlgorithm(
            SignatureAndHashAlgorithm wireAlgorithm) {
        if (signingSignatureAndHashAlgorithmContainer == null) {
            return wireAlgorithm;
        }
        return signingSignatureAndHashAlgorithmContainer.get(0);
    }

    private void setX509SubjectPrivateKey(
            X509Context x509,
            SignatureAlgorithm algorithm,
            BigInteger privateKey,
            BigInteger rsaModulus) {
        switch (algorithm) {
            case DSA:
                x509.setSubjectDsaPrivateKey(privateKey);
                return;
            case ECDSA:
                x509.setSubjectEcPrivateKey(privateKey);
                return;
            case RSA_PKCS1:
            case RSA_SSA_PSS:
                x509.setSubjectRsaPrivateKey(privateKey);
                if (rsaModulus != null) {
                    x509.setSubjectRsaModulus(rsaModulus);
                }
                return;
            default:
                return;
        }
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    @Override
    public boolean executedAsPlanned() {
        return true;
    }

    private byte[] createSignature(
            CertificateVerifyMessage message, SignatureAndHashAlgorithm algorithm, State state)
            throws CryptoException {
        byte[] toBeSigned = state.getTlsContext(getConnectionAlias()).getDigest().getRawBytes();
        Chooser chooser = state.getTlsContext(getConnectionAlias()).getChooser();
        if (state.getTlsContext(getConnectionAlias()).getChooser().getSelectedProtocolVersion().isTLS13()) {
            if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
                toBeSigned =
                        ArrayConverter.concatenate(
                                ArrayConverter.hexStringToByteArray(
                                        "2020202020202020202020202020202020202020202020202020"
                                                + "2020202020202020202020202020202020202020202020202020202020202020202020202020"),
                                CertificateVerifyConstants.CLIENT_CERTIFICATE_VERIFY.getBytes(StandardCharsets.US_ASCII),
                                new byte[] {(byte) 0x00},
                                chooser.getContext()
                                        .getTlsContext()
                                        .getDigest()
                                        .digest(
                                                chooser.getSelectedProtocolVersion(),
                                                chooser.getSelectedCipherSuite()));
            } else {
                toBeSigned =
                        ArrayConverter.concatenate(
                                ArrayConverter.hexStringToByteArray(
                                        "2020202020202020202020202020202020202020202020202020"
                                                + "2020202020202020202020202020202020202020202020202020202020202020202020202020"),
                                CertificateVerifyConstants.SERVER_CERTIFICATE_VERIFY.getBytes(StandardCharsets.US_ASCII),
                                new byte[] {(byte) 0x00},
                                chooser.getContext()
                                        .getTlsContext()
                                        .getDigest()
                                        .digest(
                                                chooser.getSelectedProtocolVersion(),
                                                chooser.getSelectedCipherSuite()));
            }
        }
        if (algorithm.getSignatureAlgorithm() == SignatureAlgorithm.RSA_SSA_PSS) {
            return createRsaPssSignature(chooser, algorithm, toBeSigned);
        } else {
            TlsSignatureUtil signatureUtil = new TlsSignatureUtil();
            signatureUtil.computeSignature(
                    chooser,
                    algorithm,
                    toBeSigned,
                    message.getSignatureComputations(algorithm.getSignatureAlgorithm()));
            return message.getSignatureComputations(algorithm.getSignatureAlgorithm())
                    .getSignatureBytes()
                    .getValue();
        }
    }

    private byte[] createRsaPssSignature(
            Chooser chooser, SignatureAndHashAlgorithm algorithm, byte[] toBeSigned)
            throws CryptoException {
        try {
            BigInteger modulus =
                    chooser.getContext()
                            .getTlsContext()
                            .getTalkingX509Context()
                            .getChooser()
                            .getSubjectRsaModulus();
            BigInteger privateKey =
                    chooser.getContext()
                            .getTlsContext()
                            .getTalkingX509Context()
                            .getChooser()
                            .getSubjectRsaPrivateKey();
            String hashName = algorithm.getHashAlgorithm().getJavaName();
            Signature signature = Signature.getInstance("RSASSA-PSS");
            signature.setParameter(
                    new PSSParameterSpec(
                            hashName,
                            "MGF1",
                            new MGF1ParameterSpec(hashName),
                            algorithm.getHashAlgorithm().getBitLength() / 8,
                            PSSParameterSpec.TRAILER_FIELD_BC));
            PrivateKey key =
                    KeyFactory.getInstance("RSA")
                            .generatePrivate(new RSAPrivateKeySpec(modulus, privateKey));
            signature.initSign(key);
            signature.update(toBeSigned);
            return signature.sign();
        } catch (Exception e) {
            throw new CryptoException("Could not create RSA-PSS signature", e);
        }
    }
}

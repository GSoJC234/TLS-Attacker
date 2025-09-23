/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.protocol.exception.PreparationException;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.CertificateRequestPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateRequestSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.*;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.cryptomator.siv.org.bouncycastle.asn1.ASN1BitStringParser;

@XmlRootElement(name = "BuildCertificateRequestAction")
public class BuildCertificateRequestAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;
    @XmlTransient private List<HandshakeMessageType> type_container = null;
    @XmlTransient private List<byte[]> certificate_request_container = null;
    @XmlTransient private List<Integer> certificate_request_context_len = null;

    @XmlTransient private List<ClientCertificateType> client_certificate_types = null;
    @XmlTransient private List<Integer> client_certificate_types_len = null;
    @XmlTransient private List<SignatureAndHashAlgorithm> signature_and_hash_algs = null;
    @XmlTransient private List<Integer> signature_and_hash_algs_len = null;

    public BuildCertificateRequestAction() {
        super();
    }

    public BuildCertificateRequestAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildCertificateRequestAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildCertificateRequestAction(String alias) {
        super(alias);
    }

    public BuildCertificateRequestAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setCertificateRequestContext(List<byte[]> certificate_request_context) {
        this.certificate_request_container = certificate_request_context;
    }

    public void setCertificateRequestContextLen(List<Integer> certificate_request_context_len) {
        this.certificate_request_context_len = certificate_request_context_len;
    }

    public void setClientCertificateTypes(List<ClientCertificateType> client_certificate_types) {
        this.client_certificate_types = client_certificate_types;
    }

    public void setClientCertificateTypesLen(List<Integer> client_certificate_types_len) {
        this.client_certificate_types_len = client_certificate_types_len;
    }

    public void setSignatureAndHashAlgorithms(List<SignatureAndHashAlgorithm> signature_and_hash_algs) {
        this.signature_and_hash_algs = signature_and_hash_algs;
    }

    public void setSignatureAndHashAlgorithmsLen(List<Integer> signature_and_hash_algs_len) {
        this.signature_and_hash_algs_len = signature_and_hash_algs_len;
    }

    public void setHandshakeType(List<HandshakeMessageType> type_container){
        this.type_container = type_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        Context context = state.getContext(getConnectionAlias());

        CertificateRequestMessage message = new CertificateRequestMessage();
        message.setShouldPrepareDefault(false);
        if(type_container != null) {
            message.setType(type_container.get(0).getValue());
        } else {
            message.setType(HandshakeMessageType.CERTIFICATE_REQUEST.getValue());
        }
        if (context.getTlsContext().getSelectedProtocolVersion() == ProtocolVersion.TLS13) {
            message.setCertificateRequestContext(certificate_request_container.get(0));
            int defaultLen = message.getCertificateRequestContext().getValue().length;
            int len = (certificate_request_context_len == null) ? defaultLen
                    : SizeCalculator.calculate(certificate_request_context_len.get(0), defaultLen, HandshakeByteLength.CERTIFICATE_REQUEST_CONTEXT_LENGTH);
            message.setCertificateRequestContextLength(len);
            message.setClientCertificateTypesCount(0);
        } else if (context.getTlsContext().getSelectedProtocolVersion() == ProtocolVersion.TLS12) {
            message.setClientCertificateTypes(convertClientCertificateTypes(client_certificate_types));
            int defaultLen1 = message.getClientCertificateTypes().getValue().length;
            int len1 = (client_certificate_types_len == null) ? defaultLen1
                    : SizeCalculator.calculate(client_certificate_types_len.get(0), defaultLen1, HandshakeByteLength.CERTIFICATES_TYPES_COUNT);
            message.setClientCertificateTypesCount(len1);

            message.setSignatureHashAlgorithms(convertSigAndHashAlgos(signature_and_hash_algs));
            int defaultLen2 = message.getSignatureHashAlgorithms().getValue().length;
            int len2 = (signature_and_hash_algs_len == null) ? defaultLen2
                    : SizeCalculator.calculate(signature_and_hash_algs_len.get(0), defaultLen2, HandshakeByteLength.SIGNATURE_HASH_ALGORITHMS_LENGTH);
            message.setSignatureHashAlgorithmsLength(len2);

            // We do not modify ASN.1 Name
            X500NameBuilder b = new X500NameBuilder(BCStyle.INSTANCE);
            b.addRDN(BCStyle.C,  "KR");
            b.addRDN(BCStyle.ST, "Seoul");      // stateOrProvinceName
            b.addRDN(BCStyle.O,  "MyOrg");
            b.addRDN(BCStyle.CN, "My Test EC CA");

            X500Name x500 = b.build();
            ASN1Primitive asn1 = x500.toASN1Primitive();
            try {
                byte[] derEncoded = asn1.getEncoded("DER");
                byte[] innerBytes = ByteBuffer.allocate(2 + derEncoded.length)
                        .putShort((short) derEncoded.length) // big-endian
                        .put(derEncoded)
                        .array();

                message.setDistinguishedNames(innerBytes);
                message.setDistinguishedNamesLength(innerBytes.length);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        message.setExtensionsLength(0);
        message.setExtensionBytes(new byte[]{});

        CertificateRequestSerializer serializer =
                new CertificateRequestSerializer(
                        message, context.getTlsContext().getSelectedProtocolVersion());
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        message.setCompleteResultingMessage(serializer.serialize());

        container.add(message);
        System.out.println("CertificateRequest: " + message);
        setExecuted(true);
    }

    private byte[] convertClientCertificateTypes(List<ClientCertificateType> typeList) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (ClientCertificateType type : typeList) {
            try {
                stream.write(type.getArrayValue());
            } catch (IOException ex) {
                throw new PreparationException(
                        "Could not prepare CertificateRequestMessage. Failed to write ClientCertificateType into message",
                        ex);
            }
        }
        return stream.toByteArray();
    }

    private byte[] convertSigAndHashAlgos(List<SignatureAndHashAlgorithm> algoList) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (SignatureAndHashAlgorithm algo : algoList) {
            try {
                stream.write(algo.getByteValue());
            } catch (IOException ex) {
                throw new PreparationException(
                        "Could not prepare CertificateRequestMessage. Failed to write SignatureAndHash Algorithm into "
                                + "message",
                        ex);
            }
        }
        return stream.toByteArray();
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

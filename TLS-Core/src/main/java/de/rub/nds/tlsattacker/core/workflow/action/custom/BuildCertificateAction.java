/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.preparator.cert.CertificateEntryPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.cert.CertificatePairSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildCertificateAction")
public class BuildCertificateAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;
    @XmlTransient private List<Integer> certificate_len = null;
    @XmlTransient private List<CertificateEntry> entry_container = null;
    @XmlTransient private List<Integer> certificate_request_context_len = null;
    @XmlTransient private List<byte[]> certificate_request_container = null;

    public BuildCertificateAction() {
        super();
    }

    public BuildCertificateAction(String alias) {
        super(alias);
    }

    public BuildCertificateAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildCertificateAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildCertificateAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setCertificate(List<CertificateEntry> entry_container) {
        this.entry_container = entry_container;
    }

    public void setCertificateLen(List<Integer> certificate_len) {
        this.certificate_len = certificate_len;
    }

    public void setCertificateRequestContextLen(List<Integer> certificate_request_context_len) {
        this.certificate_request_context_len = certificate_request_context_len;
    }

    public void setCertificateRequestContext(List<byte[]> certificate_request_context) {
        this.certificate_request_container = certificate_request_context;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        Context context = state.getContext(getConnectionAlias());

        CertificateMessage message = new CertificateMessage();
        message.setShouldPrepareDefault(false);
        message.setType(HandshakeMessageType.CERTIFICATE.getValue());

        // For changing certificates later
        List<CertificateEntry> entry_list = new ArrayList<CertificateEntry>(entry_container);
        message.setCertificateEntryList(entry_list);

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (CertificateEntry entry : entry_list) {
            CertificateEntryPreparator preparator =
                    new CertificateEntryPreparator(state.getContext(getConnectionAlias()).getChooser(), entry);
            preparator.prepare();
            CertificatePairSerializer serializer =
                    new CertificatePairSerializer(
                            entry, context.getTlsContext().getSelectedProtocolVersion());
            try {
                stream.write(serializer.serialize());
            } catch (IOException ex) {
                throw new ActionExecutionException(
                        "Could not write byte[] from CertificateEntry", ex);
            }
        }
        message.setCertificatesListBytes(stream.toByteArray());
        int defaultLen = message.getCertificatesListBytes().getValue().length;
        int len = (certificate_len == null) ? defaultLen
                : SizeCalculator.calculate(certificate_len.get(0), defaultLen, HandshakeByteLength.CERTIFICATES_LENGTH);
        message.setCertificatesListLength(len);

        if (context.getTlsContext().getSelectedProtocolVersion() == ProtocolVersion.TLS13) {
            switch (context.getConnection().getLocalConnectionEndType()) {
                case CLIENT:
                    message.setRequestContext(this.certificate_request_container.get(0));
                    int defaultLen2 = message.getRequestContext().getValue().length;
                    int len2 = (certificate_len == null) ? defaultLen2
                            : SizeCalculator.calculate(certificate_request_context_len.get(0), defaultLen2, HandshakeByteLength.CERTIFICATE_REQUEST_CONTEXT_LENGTH);
                    message.setRequestContextLength(len2);
                    break;
                case SERVER:
                    message.setRequestContext(new byte[] {});
                    message.setRequestContextLength(0);
                    break;
                default:
                    throw new IllegalStateException("Unexpected connection end type");
            }
        }

        CertificateMessageSerializer serializer =
                new CertificateMessageSerializer(
                        message, context.getTlsContext().getSelectedProtocolVersion());
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        message.setCompleteResultingMessage(serializer.serialize());

        container.add(message);
        System.out.println("Certificate: " + message);
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

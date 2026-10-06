/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.cert.CertificateEntryPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.cert.CertificatePairSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.List;

/** Adds a TLS 1.3 status_request (OCSP) response to one CertificateEntry. */
@XmlRootElement(name = "AddCertificateEntryStatusRequestExtensionAction")
public class AddCertificateEntryStatusRequestExtensionAction extends ConnectionBoundAction {

    // CertificateEntry.extensions includes the four-byte extension header and the
    // four-byte CertificateStatus header in addition to the OCSP response.
    private static final int MAX_OCSP_RESPONSE_LENGTH = 0xffff - 8;

    @XmlTransient private List<ProtocolMessage> container;
    private int certificateEntryIndex;
    @XmlTransient private byte[] ocspResponse;

    public AddCertificateEntryStatusRequestExtensionAction() {
        super();
    }

    public AddCertificateEntryStatusRequestExtensionAction(
            String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setCertificateEntryIndex(int certificateEntryIndex) {
        this.certificateEntryIndex = certificateEntryIndex;
    }

    public void setOcspResponse(byte[] ocspResponse) {
        this.ocspResponse =
                ocspResponse == null ? null : Arrays.copyOf(ocspResponse, ocspResponse.length);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        if (container == null || container.isEmpty()
                || !(container.get(0) instanceof CertificateMessage)) {
            throw new ActionExecutionException("Expected a built Certificate message");
        }
        CertificateMessage message = (CertificateMessage) container.get(0);
        ProtocolVersion version = state.getTlsContext(getConnectionAlias()).getSelectedProtocolVersion();
        if (version != ProtocolVersion.TLS13) {
            throw new ActionExecutionException(
                    "CertificateEntry status_request requires TLS 1.3");
        }
        List<CertificateEntry> entries = message.getCertificateEntryList();
        if (entries == null || certificateEntryIndex < 0 || certificateEntryIndex >= entries.size()) {
            throw new ActionExecutionException(
                    "CertificateEntry index is out of range: " + certificateEntryIndex);
        }

        UnknownExtensionMessage extension = new UnknownExtensionMessage();
        extension.setTypeConfig(ExtensionType.STATUS_REQUEST.getValue());
        extension.setDataConfig(encodeCertificateStatus(ocspResponse));
        entries.get(certificateEntryIndex).addExtension(extension);

        ByteArrayOutputStream certificateList = new ByteArrayOutputStream();
        for (CertificateEntry entry : entries) {
            new CertificateEntryPreparator(
                            state.getContext(getConnectionAlias()).getChooser(), entry)
                    .prepare();
            certificateList.writeBytes(new CertificatePairSerializer(entry, version).serialize());
        }
        message.setCertificatesListBytes(certificateList.toByteArray());
        message.setCertificatesListLength(certificateList.size());

        CertificateMessageSerializer serializer = new CertificateMessageSerializer(message, version);
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        message.setCompleteResultingMessage(serializer.serialize());
        setExecuted(true);
    }

    static byte[] encodeCertificateStatus(byte[] response) {
        if (response == null || response.length == 0
                || response.length > MAX_OCSP_RESPONSE_LENGTH) {
            throw new IllegalArgumentException(
                    "OCSP response must contain 1.." + MAX_OCSP_RESPONSE_LENGTH + " bytes");
        }
        ByteArrayOutputStream content = new ByteArrayOutputStream(4 + response.length);
        content.write(1); // CertificateStatusType.ocsp
        content.write((response.length >>> 16) & 0xff);
        content.write((response.length >>> 8) & 0xff);
        content.write(response.length & 0xff);
        content.writeBytes(response);
        return content.toByteArray();
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}

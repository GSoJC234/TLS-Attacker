/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateRequestHandler;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateRequestSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildCertificateRequestAction")
public class BuildCertificateRequestAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;

    @XmlTransient private List<HandshakeMessageType> message_type_container = null;
    @XmlTransient private List<Boolean> message_length_container = null;
    @XmlTransient private List<byte[]> certificate_request_container = null;
    @XmlTransient private List<Boolean> certificate_request_length_container = null;

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

    public void setHandshakeMessageType(List<HandshakeMessageType> message_type_container) {
        this.message_type_container = message_type_container;
    }

    public void setMessageLength(List<Boolean> message_length_container) {
        this.message_length_container = message_length_container;
    }

    public void setCertificateRequestContext(List<byte[]> certificate_request_context) {
        this.certificate_request_container = certificate_request_context;
    }

    public void setCertificateRequestContextLen(List<Boolean> certificate_request_context_len) {
        this.certificate_request_length_container = certificate_request_context_len;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        CertificateRequestMessage message = new CertificateRequestMessage();
        message.setShouldPrepareDefault(false);
        message.setType(message_type_container.get(0).getValue());
        message.setCertificateRequestContext(certificate_request_container.get(0));
        if (certificate_request_length_container.get(0)) {
            message.setCertificateRequestContextLength(certificate_request_container.get(0).length);
        }

        CertificateRequestSerializer serializer =
                new CertificateRequestSerializer(message, ProtocolVersion.TLS12);
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        if (!message_length_container.get(0)) {
            throw new ActionExecutionException("Unsupported modified message length");
        }
        message.setCompleteResultingMessage(serializer.serialize());

        CertificateRequestHandler handler =
                new CertificateRequestHandler(state.getTlsContext(getConnectionAlias()));
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
}

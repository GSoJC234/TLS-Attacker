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
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateRequestSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.*;
import de.rub.nds.tlsattacker.core.state.Context;
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

    @XmlTransient private List<byte[]> certificate_request_container = null;

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

    @Override
    public void execute(State state) throws ActionExecutionException {
        Context context = state.getContext(getConnectionAlias());

        CertificateRequestMessage message = new CertificateRequestMessage();
        message.setShouldPrepareDefault(false);
        message.setType(HandshakeMessageType.CERTIFICATE_REQUEST.getValue());
        message.setCertificateRequestContext(certificate_request_container.get(0));
        message.setCertificateRequestContextLength(
                message.getCertificateRequestContext().getValue().length);
        message.setClientCertificateTypesCount(0);

        CertificateRequestSerializer serializer =
                new CertificateRequestSerializer(
                        message, context.getTlsContext().getSelectedProtocolVersion());
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        message.setCompleteResultingMessage(serializer.serialize());

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

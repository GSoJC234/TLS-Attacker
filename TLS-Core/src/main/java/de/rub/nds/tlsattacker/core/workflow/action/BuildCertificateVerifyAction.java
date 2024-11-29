/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateVerifySerializer;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;

@XmlRootElement(name = "BuildCertificateVerifyAction")
public class BuildCertificateVerifyAction extends TlsAction {

    private List<ProtocolMessage> container = null;

    private List<HandshakeMessageType> message_type_container = null;
    private List<Boolean> message_length_container = null;
    private List<byte[]> signature_container = null;
    private List<Boolean> signature_length_container = null;

    public BuildCertificateVerifyAction(List<ProtocolMessage> container) {
        this.container = container;
    }

    public void setHandshakeMessageType(List<HandshakeMessageType> message_type_container) {
        this.message_type_container = message_type_container;
    }

    public void setMessageLength(List<Boolean> message_length_container) {
        this.message_length_container = message_length_container;
    }

    public void setSignature(List<byte[]> signature_container) {
        this.signature_container = signature_container;
    }

    public void setSignatureLength(List<Boolean> signature_length_container) {
        this.signature_length_container = signature_length_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        CertificateVerifyMessage message = new CertificateVerifyMessage();
        message.setShouldPrepareDefault(false);
        message.setType(message_type_container.get(0).getValue());
        message.setSignature(signature_container.get(0));
        if (signature_length_container.get(0)) {
            message.setSignatureLength(signature_container.get(0).length);
        }

        CertificateVerifySerializer serializer =
                new CertificateVerifySerializer(message, ProtocolVersion.TLS12);
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        if (!message_length_container.get(0)) {
            throw new ActionExecutionException("Unsupported modified message length");
        }
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

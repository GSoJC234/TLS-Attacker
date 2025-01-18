/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.ClientHelloSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildClientHelloAction")
public class BuildClientHelloAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;

    @XmlTransient private List<HandshakeMessageType> message_type_container = null;
    @XmlTransient private List<Boolean> message_length_container = null;
    @XmlTransient private List<ProtocolVersion> version_container = null;
    @XmlTransient private List<CipherSuite> suite_container = null;
    @XmlTransient private List<byte[]> random_container = null;
    @XmlTransient private List<byte[]> session_id_container = null;
    @XmlTransient private List<Boolean> session_id_length_container = null;
    @XmlTransient private List<CompressionMethod> compression_container = null;

    public BuildClientHelloAction() {
        super();
    }

    public BuildClientHelloAction(String alias) {
        super(alias);
    }

    public BuildClientHelloAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildClientHelloAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildClientHelloAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setHandshakeMessageType(List<HandshakeMessageType> message_type_container) {
        this.message_type_container = message_type_container;
    }

    public void setMessageLength(List<Boolean> message_length_container) {
        this.message_length_container = message_length_container;
    }

    public void setVersion(List<ProtocolVersion> version_container) {
        this.version_container = version_container;
    }

    public void setCipherSuite(List<CipherSuite> suite_container) {
        this.suite_container = suite_container;
    }

    public void setRandom(List<byte[]> random_container) {
        this.random_container = random_container;
    }

    public void setSessionId(List<byte[]> session_id_container) {
        this.session_id_container = session_id_container;
    }

    public void setSessionIdLength(List<Boolean> session_id_length_container) {
        this.session_id_length_container = session_id_length_container;
    }

    public void setCompression(List<CompressionMethod> compression_container) {
        this.compression_container = compression_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        ClientHelloMessage message = new ClientHelloMessage();
        message.setShouldPrepareDefault(false);

        message.setType(message_type_container.get(0).getValue());
        message.setProtocolVersion(version_container.get(0).getValue());
        message.setCipherSuites(suite_container.get(0).getByteValue());
        message.setCipherSuiteLength(suite_container.get(0).getByteValue().length);
        message.setRandom(random_container.get(0));
        message.setSessionId(session_id_container.get(0));
        if (session_id_length_container.get(0)) {
            message.setSessionIdLength(session_id_container.get(0).length);
        }
        message.setCompressions(compression_container.get(0).getArrayValue());
        message.setCompressionLength(compression_container.get(0).getArrayValue().length);

        ClientHelloSerializer serializer =
                new ClientHelloSerializer(message, ProtocolVersion.TLS13);
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

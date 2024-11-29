/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.ServerHelloSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.List;

@XmlRootElement(name = "BuildServerHelloAction")
public class BuildServerHelloAction extends TlsAction {

    private List<ProtocolMessage> container = null;

    private List<HandshakeMessageType> message_type_container = null;
    private List<Boolean> message_length_container = null;
    private List<ProtocolVersion> version_container = null;
    private List<CipherSuite> suite_container = null;
    private List<byte[]> random_container = null;
    private List<byte[]> session_id_container = null;
    private List<Boolean> session_id_length_container = null;
    private List<CompressionMethod> compression_container = null;
    private List<List<ExtensionMessage>> extension_container = null;

    public BuildServerHelloAction() {}
    ;

    public BuildServerHelloAction(List<ProtocolMessage> container) {
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

    public void setExtension(List<List<ExtensionMessage>> extension_container) {
        this.extension_container = extension_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        ServerHelloMessage message = new ServerHelloMessage();
        message.setShouldPrepareDefault(false);
        message.setType(HandshakeMessageType.SERVER_HELLO.getValue());
        message.setProtocolVersion(version_container.get(0).getValue());
        message.setSelectedCipherSuite(suite_container.get(0).getByteValue());
        message.setRandom(random_container.get(0));
        message.setSessionId(session_id_container.get(0));
        if (session_id_length_container.get(0)) {
            message.setSessionIdLength(session_id_container.get(0).length);
        }
        message.setSelectedCompressionMethod(compression_container.get(0).getValue());
        List<ExtensionMessage> extensionMessageList = new ArrayList<ExtensionMessage>();
        for (List<ExtensionMessage> element : extension_container) {
            extensionMessageList.add(element.get(0));
        }
        message.setExtensions(extensionMessageList);

        ServerHelloSerializer serializer = new ServerHelloSerializer(message);
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

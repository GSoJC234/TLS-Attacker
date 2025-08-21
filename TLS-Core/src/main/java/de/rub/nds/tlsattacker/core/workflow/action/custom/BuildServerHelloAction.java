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
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.*;
import de.rub.nds.tlsattacker.core.protocol.serializer.ServerHelloSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildServerHelloAction")
public class BuildServerHelloAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;

    @XmlTransient private List<ProtocolVersion> version_container = null;
    @XmlTransient private List<CipherSuite> suite_container = null;
    @XmlTransient private List<byte[]> random_container = null;
    @XmlTransient private List<byte[]> session_id_container = null;
    @XmlTransient private List<Integer> sessionIdLen = null;
    @XmlTransient private List<CompressionMethod> compression_container = null;

    public BuildServerHelloAction() {
        super();
    }

    public BuildServerHelloAction(String alias) {
        super(alias);
    }

    public BuildServerHelloAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildServerHelloAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildServerHelloAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
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

    public void setSessionIdLen(List<Integer> sessionIdLen){
        this.sessionIdLen = sessionIdLen;
    }

    public void setCompression(List<CompressionMethod> compression_container) {
        this.compression_container = compression_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        ServerHelloMessage message = new ServerHelloMessage();
        message.setShouldPrepareDefault(false);

        message.setType(HandshakeMessageType.SERVER_HELLO.getValue());
        message.setProtocolVersion(version_container.get(0).getValue());
        message.setSelectedCipherSuite(suite_container.get(0).getByteValue());
        message.setUnixTime(new byte[] {0x00, 0x00}); // dummy
        message.setRandom(random_container.get(0));
        message.setSessionId(session_id_container.get(0));
        int defaultLen = message.getSessionId().getValue().length;
        int len = (sessionIdLen == null) ? defaultLen
                : SizeCalculator.calculate(sessionIdLen.get(0), defaultLen, HandshakeByteLength.SESSION_ID_LENGTH);
        message.setSessionIdLength(len);
        message.setSelectedCompressionMethod(compression_container.get(0).getValue());

        ServerHelloSerializer serializer = new ServerHelloSerializer(message);
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        message.setCompleteResultingMessage(serializer.serialize());

        container.add(message);
        System.out.println("ServerHello: " + message);
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

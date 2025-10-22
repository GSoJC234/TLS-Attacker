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
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.ClientHelloSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildClientHelloAction")
public class BuildClientHelloAction extends ConnectionBoundAction {



    @XmlTransient protected List<ProtocolMessage> container = null;
    @XmlTransient private List<HandshakeMessageType> type_container = null;
    @XmlTransient private List<ProtocolVersion> version_container = null;
    @XmlTransient private List<Integer> cipherSuitesLen = null;
    @XmlTransient private List<CipherSuite> suite_container = null;
    @XmlTransient private List<byte[]> random_container = null;
    @XmlTransient private List<Integer> sessionIdLen = null;
    @XmlTransient private List<byte[]> session_id_container = null;
    @XmlTransient private List<Integer> compression_len = null;
    @XmlTransient private List<CompressionMethod> compression_container = null;

    private static final int RANDOM_LENGTH_FALLBACK = 4393139;

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

    public void setVersion(List<ProtocolVersion> version_container) {
        this.version_container = version_container;
    }

    public void setCipherSuites(List<CipherSuite> suite_container) {
        this.suite_container = suite_container;
    }

    public void setRandom(List<byte[]> random_container) {
        this.random_container = random_container;
    }

    public void setSessionId(List<byte[]> session_id_container) {
        this.session_id_container = session_id_container;
    }

    public void setCompressions(List<CompressionMethod> compression_container) {
        this.compression_container = compression_container;
    }

    public void setCipherSuitesLen(List<Integer> cipherSuitesLen) {
        this.cipherSuitesLen = cipherSuitesLen;
    }

    public void setSessionIdLen(List<Integer> sessionIdLen) {
        this.sessionIdLen = sessionIdLen;
    }

    public void setCompressionsLen(List<Integer> compression_len) {
        this.compression_len = compression_len;
    }

    public void setHandshakeType(List<HandshakeMessageType> type_container){
        this.type_container = type_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        ClientHelloMessage message = new ClientHelloMessage();
        message.setShouldPrepareDefault(false);

        if(this.type_container != null) {
            message.setType(this.type_container.get(0).getValue());
        } else {
            message.setType(HandshakeMessageType.CLIENT_HELLO.getValue());
        }

        message.setProtocolVersion(version_container.get(0).getValue());

        message.setCipherSuites(serializeCipherSuites(suite_container));
        int defaultLen1 = message.getCipherSuites().getValue().length;
        int len1 = (cipherSuitesLen == null) ? defaultLen1
                : SizeCalculator.calculate(cipherSuitesLen.get(0), defaultLen1, HandshakeByteLength.CIPHER_SUITES_LENGTH);
        message.setCipherSuiteLength(len1);

        message.setUnixTime(new byte[] {0x00, 0x00}); // dummy
        message.setRandom(random_container.get(0));

        message.setSessionId(session_id_container.get(0));
        int defaultLen2 = message.getSessionId().getValue().length;
        int len2 = (sessionIdLen == null) ? defaultLen2
                : SizeCalculator.calculate(sessionIdLen.get(0), defaultLen2, HandshakeByteLength.SESSION_ID_LENGTH);
        message.setSessionIdLength(len2);

        message.setCompressions(serializeCompressionMethods(compression_container));
        int defaultLen3 = message.getCompressions().getValue().length;
        int len3 = (compression_len == null) ? defaultLen3
                : SizeCalculator.calculate(compression_len.get(0), defaultLen3, HandshakeByteLength.COMPRESSION_LENGTH);
        message.setCompressionLength(len3);

        ClientHelloSerializer serializer =
                new ClientHelloSerializer(message, ProtocolVersion.TLS13);
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        message.setCompleteResultingMessage(serializer.serialize());

        container.add(message);
        setExecuted(true);
    }

    private byte[] serializeCipherSuites(List<CipherSuite> suites) {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            for (CipherSuite suite : suites) {
                outputStream.write(suite.getByteValue());
            }
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to serialize CipherSuites", e);
        }
    }

    private byte[] serializeCompressionMethods(List<CompressionMethod> methods) {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            for (CompressionMethod method : methods) {
                outputStream.write(method.getArrayValue());
            }
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to serialize CompressionMethods", e);
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
}

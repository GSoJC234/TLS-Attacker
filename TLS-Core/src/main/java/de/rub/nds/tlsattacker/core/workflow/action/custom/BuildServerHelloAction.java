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
import de.rub.nds.tlsattacker.core.protocol.handler.ServerHelloHandler;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.serializer.ServerHelloSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildServerHelloAction")
public class BuildServerHelloAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;

    @XmlTransient private List<HandshakeMessageType> message_type_container = null;
    @XmlTransient private List<Boolean> message_length_container = null;
    @XmlTransient private List<ProtocolVersion> version_container = null;
    @XmlTransient private List<CipherSuite> suite_container = null;
    @XmlTransient private List<byte[]> random_container = null;
    @XmlTransient private List<byte[]> session_id_container = null;
    @XmlTransient private List<Boolean> session_id_length_container = null;
    @XmlTransient private List<CompressionMethod> compression_container = null;
    @XmlTransient private List<List<?>> extension_container = null;

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

    public void setExtension(List<List<?>> extension_container) {
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
        message.setExtensionBytes(generateExtensionMessages());
        message.setExtensionsLength(message.getExtensionBytes().getValue().length);

        ServerHelloSerializer serializer = new ServerHelloSerializer(message);
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        if (!message_length_container.get(0)) {
            throw new ActionExecutionException("Unsupported modified message length");
        }
        message.setCompleteResultingMessage(serializer.serialize());

        ServerHelloHandler handler = message.getHandler(state.getTlsContext(getConnectionAlias()));
        handler.adjustContext(message);
        message.setAdjustContext(false);

        container.add(message);
        setExecuted(true);
    }

    private byte[] generateExtensionMessages() {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        try {
            for (List<?> extension : extension_container) {
                Object element = extension.get(0);
                if (element instanceof NamedGroup) {
                    EllipticCurvesExtensionMessage message = new EllipticCurvesExtensionMessage();
                    message.setSupportedGroups(((NamedGroup) element).getValue());
                    message.setSupportedGroupsLength(
                            message.getSupportedGroups().getValue().length);
                    message.setExtensionType(ExtensionType.ELLIPTIC_CURVES.getValue());

                    EllipticCurvesExtensionSerializer serializer =
                            new EllipticCurvesExtensionSerializer(message);
                    message.setExtensionContent(serializer.serializeExtensionContent());
                    message.setExtensionLength(message.getExtensionContent().getValue().length);

                    byteStream.write(serializer.serialize());
                } else if (element instanceof ProtocolVersion) {
                    SupportedVersionsExtensionMessage message =
                            new SupportedVersionsExtensionMessage();
                    message.setSupportedVersions(((ProtocolVersion) element).getValue());
                    message.setExtensionType(ExtensionType.SUPPORTED_VERSIONS.getValue());

                    SupportedVersionsExtensionSerializer serializer =
                            new SupportedVersionsExtensionSerializer(message);
                    message.setExtensionContent(serializer.serializeExtensionContent());
                    message.setExtensionLength(message.getExtensionContent().getValue().length);
                    message.setExtensionBytes(serializer.serialize());

                    byteStream.write(message.getExtensionBytes().getValue());
                } else if (element instanceof SignatureAndHashAlgorithm) {
                    SignatureAndHashAlgorithmsExtensionMessage message =
                            new SignatureAndHashAlgorithmsExtensionMessage();
                    message.setSignatureAndHashAlgorithms(
                            ((SignatureAndHashAlgorithm) element).getByteValue());
                    message.setSignatureAndHashAlgorithmsLength(
                            message.getSignatureAndHashAlgorithms().getValue().length);
                    message.setExtensionType(
                            ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS.getValue());

                    SignatureAndHashAlgorithmsExtensionSerializer serializer =
                            new SignatureAndHashAlgorithmsExtensionSerializer(message);
                    message.setExtensionContent(serializer.serializeExtensionContent());
                    message.setExtensionLength(message.getExtensionContent().getValue().length);

                    byteStream.write(serializer.serialize());
                } else if (element instanceof KeyShareEntry) {
                    KeyShareEntrySerializer serializer =
                            new KeyShareEntrySerializer((KeyShareEntry) element);
                    KeyShareExtensionMessage message = new KeyShareExtensionMessage();
                    message.setExtensionType(ExtensionType.KEY_SHARE.getValue());

                    message.setKeyShareListBytes(serializer.serialize());
                    KeyShareExtensionSerializer serializer2 =
                            new KeyShareExtensionSerializer(message, ConnectionEndType.SERVER);
                    message.setExtensionContent(serializer2.serializeExtensionContent());
                    message.setExtensionLength(message.getExtensionContent().getValue().length);

                    message.setExtensionBytes(serializer2.serialize());

                    byteStream.write(message.getExtensionBytes().getValue());
                }
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return byteStream.toByteArray();
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

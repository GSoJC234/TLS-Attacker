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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
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

@XmlRootElement(name = "BuildWrongSideClientHelloAction")
public class BuildWrongSideClientHelloAction extends ConnectionBoundAction {

    private static final int BITS_IN_A_BYTE = 8;

    @XmlTransient private List<ProtocolMessage> container = null;
    @XmlTransient private List<HandshakeMessageType> typeContainer = null;
    @XmlTransient private List<ProtocolVersion> versionContainer = null;
    @XmlTransient private List<CipherSuite> suiteContainer = null;
    @XmlTransient private List<byte[]> randomContainer = null;
    @XmlTransient private List<CompressionMethod> compressionContainer = null;

    public BuildWrongSideClientHelloAction() {
        super();
    }

    public BuildWrongSideClientHelloAction(String alias) {
        super(alias);
    }

    public BuildWrongSideClientHelloAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildWrongSideClientHelloAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildWrongSideClientHelloAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setHandshakeType(List<HandshakeMessageType> typeContainer) {
        this.typeContainer = typeContainer;
    }

    public void setVersion(List<ProtocolVersion> versionContainer) {
        this.versionContainer = versionContainer;
    }

    public void setCipherSuite(List<CipherSuite> suiteContainer) {
        this.suiteContainer = suiteContainer;
    }

    public void setRandom(List<byte[]> randomContainer) {
        this.randomContainer = randomContainer;
    }

    public void setCompression(List<CompressionMethod> compressionContainer) {
        this.compressionContainer = compressionContainer;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        validateInputs();

        ClientHelloMessage message = new ClientHelloMessage();
        message.setShouldPrepareDefault(false);
        message.setType(HandshakeMessageType.CLIENT_HELLO.getValue());

        ProtocolVersion selectedVersion =
                versionContainer != null && !versionContainer.isEmpty()
                        ? versionContainer.get(0)
                        : state.getTlsContext(getConnectionAlias())
                                .getChooser()
                                .getSelectedProtocolVersion();
        if (selectedVersion == null) {
            throw new ActionExecutionException("No protocol version configured");
        }
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());
        if (tlsContext.getSelectedProtocolVersion() == null) {
            tlsContext.setSelectedProtocolVersion(selectedVersion);
        }
        message.setProtocolVersion(selectedVersion.getValue());
        message.setAdjustContext(false);

        message.setUnixTime(new byte[] {0x00, 0x00});
        message.setRandom(randomContainer.get(0));

        // The wrong-side ClientHello used for CVE-2021-44718 must be a real ClientHello
        // body, but it intentionally does not reuse the server-side session id.
        message.setSessionId(new byte[] {});
        message.setSessionIdLength(0);

        message.setCipherSuites(serializeCipherSuites(suiteContainer));
        message.setCipherSuiteLength(message.getCipherSuites().getValue().length);

        message.setCompressions(serializeCompressionMethods(compressionContainer));
        message.setCompressionLength(message.getCompressions().getValue().length);

        byte[] extensions = buildDefaultClientHelloExtensions();
        message.setExtensionBytes(extensions);
        message.setExtensionsLength(extensions.length);

        ClientHelloSerializer serializer = new ClientHelloSerializer(message, selectedVersion);
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        message.setCompleteResultingMessage(serializer.serialize());

        container.add(message);
        setExecuted(true);
    }

    private void validateInputs() {
        if (typeContainer != null
                && !typeContainer.isEmpty()
                && typeContainer.get(0) != HandshakeMessageType.CLIENT_HELLO) {
            throw new ActionExecutionException(
                    "BuildWrongSideClientHelloAction requires CLIENT_HELLO handshake type");
        }
        if (container == null) {
            throw new ActionExecutionException("No output container configured");
        }
        if (suiteContainer == null || suiteContainer.isEmpty()) {
            throw new ActionExecutionException("No cipher suite configured");
        }
        if (randomContainer == null || randomContainer.isEmpty() || randomContainer.get(0) == null) {
            throw new ActionExecutionException("No ClientHello random configured");
        }
        if (compressionContainer == null || compressionContainer.isEmpty()) {
            compressionContainer = List.of(CompressionMethod.NULL);
        }
    }

    private byte[] buildDefaultClientHelloExtensions() {
        try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            writeExtension(
                    output,
                    ExtensionType.ELLIPTIC_CURVES.getValue(),
                    vector16(NamedGroup.SECP256R1.getValue(), NamedGroup.SECP384R1.getValue()));
            writeExtension(output, ExtensionType.EC_POINT_FORMATS.getValue(), vector8(new byte[] {0x00}));
            writeExtension(
                    output,
                    ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS.getValue(),
                    vector16(
                            SignatureAndHashAlgorithm.RSA_SHA256.getByteValue(),
                            SignatureAndHashAlgorithm.RSA_SHA384.getByteValue(),
                            SignatureAndHashAlgorithm.ECDSA_SHA256.getByteValue()));
            writeExtension(output, ExtensionType.EXTENDED_MASTER_SECRET.getValue(), new byte[] {});
            return output.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to build wrong-side ClientHello extensions", e);
        }
    }

    private void writeExtension(ByteArrayOutputStream output, byte[] type, byte[] data)
            throws IOException {
        output.write(type);
        writeUint16(output, data.length);
        output.write(data);
    }

    private byte[] vector16(byte[]... values) throws IOException {
        try (ByteArrayOutputStream body = new ByteArrayOutputStream()) {
            for (byte[] value : values) {
                body.write(value);
            }
            byte[] data = body.toByteArray();
            try (ByteArrayOutputStream vector = new ByteArrayOutputStream()) {
                writeUint16(vector, data.length);
                vector.write(data);
                return vector.toByteArray();
            }
        }
    }

    private byte[] vector8(byte[] data) throws IOException {
        try (ByteArrayOutputStream vector = new ByteArrayOutputStream()) {
            vector.write(data.length);
            vector.write(data);
            return vector.toByteArray();
        }
    }

    private void writeUint16(ByteArrayOutputStream output, int value) {
        output.write((value >> BITS_IN_A_BYTE) & 0xff);
        output.write(value & 0xff);
    }

    private byte[] serializeCipherSuites(List<CipherSuite> suites) {
        try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            for (CipherSuite suite : suites) {
                output.write(suite.getByteValue());
            }
            return output.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to serialize CipherSuites", e);
        }
    }

    private byte[] serializeCompressionMethods(List<CompressionMethod> methods) {
        try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            for (CompressionMethod method : methods) {
                output.write(method.getArrayValue());
            }
            return output.toByteArray();
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

/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EncryptedServerNameIndicationExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.PreSharedKeyExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @param <T> The HandshakeMessage that should be prepared
 */
public abstract class HandshakeMessagePreparator<T extends HandshakeMessage<?>>
        extends ProtocolMessagePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HandshakeMessagePreparator(Chooser chooser, T message) {
        super(chooser, message);
    }

    protected void prepareMessageLength(int length) {
        message.setLength(length);
        LOGGER.debug("Length: " + message.getLength().getValue());
    }

    private void prepareMessageType(HandshakeMessageType type) {
        message.setType(type.getValue());
        LOGGER.debug("Type: " + message.getType().getValue());
    }

    private void prepareMessageContent(byte[] content) {
        message.setMessageContent(content);
        LOGGER.debug(
                "Handshake message content: "
                        + ArrayConverter.bytesToHexString(message.getMessageContent().getValue()));
    }

    @Override
    protected void prepareProtocolMessageContents() {
        prepareHandshakeMessageContents();
        prepareEncapsulatingFields();
    }

    public void prepareEncapsulatingFields() {
        HandshakeMessageSerializer<?> serializer =
                message.getSerializer(chooser.getContext().getTlsContext());
        byte[] content = serializer.serializeHandshakeMessageContent();
        prepareMessageContent(content);
        if (!(message instanceof DtlsHandshakeMessageFragment)) {
            prepareMessageLength(content.length);
            prepareMessageType(message.getHandshakeMessageType());
        }
    }

    protected abstract void prepareHandshakeMessageContents();

    protected void prepareExtensions() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        if (message.getExtensions() != null) {
            for (ExtensionMessage extensionMessage : message.getExtensions()) {
                HandshakeMessageType handshakeMessageType = message.getHandshakeMessageType();
                if (extensionMessage instanceof KeyShareExtensionMessage
                        && message instanceof ServerHelloMessage) {
                    ServerHelloMessage serverHello = (ServerHelloMessage) message;
                    KeyShareExtensionMessage ksExt = (KeyShareExtensionMessage) extensionMessage;
                    if (serverHello.setRetryRequestModeInKeyShare()) {
                        ksExt.setRetryRequestMode(true);
                    }
                }
                extensionMessage.getPreparator(chooser.getContext().getTlsContext()).prepare();
                try {
                    stream.write(extensionMessage.getExtensionBytes().getValue());
                } catch (IOException ex) {
                    throw new PreparationException("Could not write ExtensionBytes to byte[]", ex);
                }
            }
        }
        message.setExtensionBytes(stream.toByteArray());
        LOGGER.debug(
                "ExtensionBytes: "
                        + ArrayConverter.bytesToHexString(message.getExtensionBytes().getValue()));
    }

    protected void afterPrepareExtensions() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        if (message.getExtensions() != null) {
            for (ExtensionMessage extensionMessage : message.getExtensions()) {
                Preparator preparator =
                        extensionMessage.getPreparator(chooser.getContext().getTlsContext());
                if (extensionMessage instanceof PreSharedKeyExtensionMessage
                        && message instanceof ClientHelloMessage
                        && chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
                    ((PreSharedKeyExtensionPreparator) preparator)
                            .setClientHello((ClientHelloMessage) message);
                    preparator.afterPrepare();
                } else if (extensionMessage instanceof EncryptedServerNameIndicationExtensionMessage
                        && message instanceof ClientHelloMessage
                        && chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
                    ClientHelloMessage clientHelloMessage = (ClientHelloMessage) message;
                    ((EncryptedServerNameIndicationExtensionPreparator) preparator)
                            .setClientHelloMessage(clientHelloMessage);
                    preparator.afterPrepare();
                }
                if (extensionMessage.getExtensionBytes() != null
                        && extensionMessage.getExtensionBytes().getValue() != null) {
                    try {
                        stream.write(extensionMessage.getExtensionBytes().getValue());
                    } catch (IOException ex) {
                        throw new PreparationException(
                                "Could not write ExtensionBytes to byte[]", ex);
                    }
                } else {
                    LOGGER.debug(
                            "If we are in a SSLv2 or SSLv3 Connection we do not add extensions, as SSL did not contain extensions");
                    LOGGER.debug("If however, the extensions are prepared, we will add them");
                }
            }
        }
        message.setExtensionBytes(stream.toByteArray());
        prepareEncapsulatingFields();
        LOGGER.debug(
                "ExtensionBytes: "
                        + ArrayConverter.bytesToHexString(message.getExtensionBytes().getValue()));
    }

    protected void prepareExtensionLength() {
        message.setExtensionsLength(message.getExtensionBytes().getValue().length);
        LOGGER.debug("ExtensionLength: " + message.getExtensionsLength().getValue());
    }
}

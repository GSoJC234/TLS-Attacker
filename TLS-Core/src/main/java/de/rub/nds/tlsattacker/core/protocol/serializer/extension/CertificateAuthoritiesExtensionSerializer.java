/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateAuthoritiesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateAuthoritiesExtensionSerializer
        extends ExtensionSerializer<CertificateAuthoritiesExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final CertificateAuthoritiesExtensionMessage msg;

    public CertificateAuthoritiesExtensionSerializer(CertificateAuthoritiesExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing CertificateAuthoritiesExtensionMessage");
        writeDistinguishedNameLength(msg);
        writeDistinguishedNames(msg);
        return getAlreadySerialized();
    }

    private void writeDistinguishedNameLength(CertificateAuthoritiesExtensionMessage msg) {
        appendInt(
                msg.getDistinguishedNameLength().getValue(),
                ExtensionByteLength.DISTINGUISHED_NAME_LENGTH);
        LOGGER.debug("DistinguishedNameLength: " + msg.getDistinguishedNameLength().getValue());
    }

    private void writeDistinguishedNames(CertificateAuthoritiesExtensionMessage msg) {
        appendBytes(msg.getDistinguishedNames().getValue());
        LOGGER.debug("DistinguishedNames: {}", msg.getDistinguishedNames().getValue());
    }
}

/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateAuthoritiesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateAuthoritiesExtensionParser
        extends ExtensionParser<CertificateAuthoritiesExtensionMessage>{

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificateAuthoritiesExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(CertificateAuthoritiesExtensionMessage msg) {
        LOGGER.debug("Parsing CertificateAuthoritiesExtensionMessage");
        if (getTlsContext().getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
            parseDistinguishedNameLength(msg);
            parseDistinguishedNames(msg);
            LOGGER.debug("Distinguished names: {}", msg.getDistinguishedNames().getValue());
        }
    }

    /**
     * Reads the next bytes as the distinguishedNameLength of the Extension and writes them in the
     * message
     *
     * @param msg Message to write in
     */
    private void parseDistinguishedNameLength(CertificateAuthoritiesExtensionMessage msg) {
        msg.setDistinguishedNameLength(
                parseIntField(ExtensionByteLength.DISTINGUISHED_NAME_LENGTH));
        LOGGER.debug("DistinguishedNamesLength: " + msg.getDistinguishedNameLength().getValue());
    }
    /**
     * Reads the next bytes as the distinguishedNames of the Extension and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseDistinguishedNames(CertificateAuthoritiesExtensionMessage msg) {
        msg.setDistinguishedNames(parseByteArrayField(msg.getDistinguishedNameLength().getValue()));
        LOGGER.debug("DistinguishedNames: {}", msg.getDistinguishedNameLength().getValue());
    }
}

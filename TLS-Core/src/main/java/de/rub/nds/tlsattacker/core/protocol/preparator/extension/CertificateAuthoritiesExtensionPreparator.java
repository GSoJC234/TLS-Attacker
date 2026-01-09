/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.protocol.exception.PreparationException;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateAuthoritiesExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateAuthoritiesExtensionPreparator
        extends ExtensionPreparator<CertificateAuthoritiesExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final CertificateAuthoritiesExtensionMessage msg;

    public CertificateAuthoritiesExtensionPreparator(
            Chooser chooser, CertificateAuthoritiesExtensionMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing CertificateAuthoritiesExtensionMessage");
        prepareDistinguishedNames(msg);
        prepareDistinguishedNameLength(msg);
    }

    private void prepareDistinguishedNames(CertificateAuthoritiesExtensionMessage msg) {
        msg.setDistinguishedNames(chooser.getConfig().getDistinguishedNames());
        LOGGER.debug("DistinguishedNames: {}", msg.getDistinguishedNames().getValue());
    }

    private void prepareDistinguishedNameLength(CertificateAuthoritiesExtensionMessage msg) {
        msg.setDistinguishedNameLength(msg.getDistinguishedNames().getValue().length);
        LOGGER.debug("DistinguishedNameLength: " + msg.getDistinguishedNameLength().getValue());
    }
}

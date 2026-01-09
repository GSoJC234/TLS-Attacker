/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateAuthoritiesExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateAuthoritiesExtensionHandler
        extends ExtensionHandler<CertificateAuthoritiesExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificateAuthoritiesExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(CertificateAuthoritiesExtensionMessage message) {
        byte[] certificateAuthoritiesBytes = message.getDistinguishedNames().getValue();
        if (certificateAuthoritiesBytes.length == 0) {
            throw new AdjustmentException(
                    "Could not create reasonable CertificateAuthorities from CertificateAuthoritiesBytes"
            );
        }
        tlsContext.setDistinguishedNames(certificateAuthoritiesBytes);
    }
}

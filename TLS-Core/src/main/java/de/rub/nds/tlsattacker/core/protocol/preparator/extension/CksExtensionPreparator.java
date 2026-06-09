/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.CksSigSpec;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CksExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CksExtensionPreparator extends ExtensionPreparator<CksExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final CksExtensionMessage message;

    public CksExtensionPreparator(Chooser chooser, CksExtensionMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        if (message.getCksSigSpecBytes() == null
                || message.getCksSigSpecBytes().getValue() == null) {
            message.setCksSigSpecBytes(new byte[] {CksSigSpec.NATIVE.getValue()});
        }
        LOGGER.debug("Prepared CKS extension bytes {}", message.getCksSigSpecBytes().getValue());
    }
}

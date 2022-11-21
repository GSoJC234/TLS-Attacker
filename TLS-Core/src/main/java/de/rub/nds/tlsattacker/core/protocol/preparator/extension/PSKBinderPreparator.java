/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKBinder;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PSKBinderPreparator extends Preparator<PSKBinder> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PSKBinder pskBinder;

    public PSKBinderPreparator(Chooser chooser, PSKBinder pskBinder) {
        super(chooser, pskBinder);
        this.pskBinder = pskBinder;
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing PSKBinder");
        prepareBinderValue();
    }

    private void prepareBinderValue() {
        try {
            HKDFAlgorithm hkdfAlgorithm = AlgorithmResolver.getHKDFAlgorithm(pskBinder.getBinderCipherConfig());
            int macLen = Mac.getInstance(hkdfAlgorithm.getMacAlgorithm().getJavaName()).getMacLength();

            pskBinder.setBinderEntry(new byte[macLen]);
            pskBinder.setBinderEntryLength(pskBinder.getBinderEntry().getValue().length);
        } catch (NoSuchAlgorithmException ex) {
            LOGGER.warn(ex);
        }
    }

}

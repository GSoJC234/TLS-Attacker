/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.io.ByteArrayOutputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECPointFormatExtensionPreparator extends ExtensionPreparator<ECPointFormatExtensionMessage> {

    private final ECPointFormatExtensionMessage msg;

    public ECPointFormatExtensionPreparator(TlsContext context, ECPointFormatExtensionMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing ECPointFormatExtensionMessage");
        preparePointFormats(msg);
        preparePointFormatsLength(msg);
    }

    private void preparePointFormats(ECPointFormatExtensionMessage msg) {
        msg.setPointFormats(createPointFormatsByteArray());
        LOGGER.debug("PointFormats: " + ArrayConverter.bytesToHexString(msg.getPointFormats().getValue()));
    }

    private byte[] createPointFormatsByteArray() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (ECPointFormat format : context.getConfig().getPointFormats()) {
            stream.write(format.getValue());
        }
        return stream.toByteArray();
    }

    private void preparePointFormatsLength(ECPointFormatExtensionMessage msg) {
        msg.setPointFormatsLength(msg.getPointFormats().getValue().length);
        LOGGER.debug("PointFormatsLength: " + msg.getPointFormatsLength().getValue());
    }

}
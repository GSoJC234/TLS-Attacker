/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.frame;

import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.handler.frame.HandshakeDoneFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.HandshakeDoneFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.HandshakeDoneFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.HandshakeDoneFrameSerializer;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** Frame only consists of the frame type. */
@XmlRootElement
public class HandshakeDoneFrame extends QuicFrame<HandshakeDoneFrame> {

    public HandshakeDoneFrame() {
        super(QuicFrameType.HANDSHAKE_DONE_FRAME);
    }

    @Override
    public HandshakeDoneFrameHandler getHandler(QuicContext context) {
        return new HandshakeDoneFrameHandler(context);
    }

    @Override
    public HandshakeDoneFrameSerializer getSerializer(QuicContext context) {
        return new HandshakeDoneFrameSerializer(this);
    }

    @Override
    public HandshakeDoneFramePreparator getPreparator(QuicContext context) {
        return new HandshakeDoneFramePreparator(context.getChooser(), this);
    }

    @Override
    public HandshakeDoneFrameParser getParser(QuicContext context, InputStream stream) {
        return new HandshakeDoneFrameParser(stream);
    }
}

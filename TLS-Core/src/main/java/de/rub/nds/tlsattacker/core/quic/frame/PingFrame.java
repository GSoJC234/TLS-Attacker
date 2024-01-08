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
import de.rub.nds.tlsattacker.core.quic.handler.frame.PingFrameHandler;
import de.rub.nds.tlsattacker.core.quic.handler.frame.QuicFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.PingFrameParser;
import de.rub.nds.tlsattacker.core.quic.parser.frame.QuicFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.PingFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.PingFrameSerializer;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class PingFrame extends QuicFrame {

    public PingFrame() {
        super(QuicFrameType.PING_FRAME);
    }

    @Override
    public QuicFrameHandler<PingFrame> getHandler(QuicContext context) {
        return new PingFrameHandler(context);
    }

    @Override
    public PingFrameSerializer getSerializer(QuicContext context) {
        return new PingFrameSerializer(this);
    }

    @Override
    public PingFramePreparator getPreparator(QuicContext context) {
        return new PingFramePreparator(context.getChooser(), this);
    }

    @Override
    public QuicFrameParser<PingFrame> getParser(QuicContext context, InputStream stream) {
        return new PingFrameParser(stream);
    }
}
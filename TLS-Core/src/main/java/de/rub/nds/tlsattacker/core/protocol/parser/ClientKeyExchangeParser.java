/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.InputStream;

/**
 * @param <T>
 *            The ClientKeyExchangeMessage that should be parsed
 */
public abstract class ClientKeyExchangeParser<T extends ClientKeyExchangeMessage> extends HandshakeMessageParser<T> {

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param tlsContext
     *                   A Config used in the current tlsContext
     */
    public ClientKeyExchangeParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }
}

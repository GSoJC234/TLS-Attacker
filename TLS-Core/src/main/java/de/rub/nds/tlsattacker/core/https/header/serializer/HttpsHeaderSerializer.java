/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.https.header.serializer;

import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;

public class HttpsHeaderSerializer extends Serializer<HttpsHeader> {

    private final HttpsHeader header;

    public HttpsHeaderSerializer(HttpsHeader header) {
        super();
        this.header = header;
    }

    @Override
    protected byte[] serializeBytes() {
        appendBytes(header.getHeaderName().getValue().getBytes());
        appendBytes(": ".getBytes());
        appendBytes(header.getHeaderValue().getValue().getBytes());
        appendBytes("\r\n".getBytes());
        return getAlreadySerialized();
    }

}

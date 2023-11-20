/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http.header;

import de.rub.nds.tlsattacker.core.http.header.preparator.HostHeaderPreparator;
import de.rub.nds.tlsattacker.core.http.header.serializer.HttpHeaderSerializer;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import java.io.InputStream;

public class HostHeader extends HttpHeader {

    public HostHeader() {}

    @Override
    public HostHeaderPreparator getPreparator(HttpContext httpContext) {
        return new HostHeaderPreparator(httpContext.getChooser(), this);
    }

    @Override
    public Parser<?> getParser(HttpContext context, InputStream stream) {
        return null; // TODO Parser is not used
    }

    @Override
    public Serializer<?> getSerializer(HttpContext context) {
        return new HttpHeaderSerializer(this);
    }

    @Override
    public Handler<?> getHandler(HttpContext context) {
        return null;
    }
}

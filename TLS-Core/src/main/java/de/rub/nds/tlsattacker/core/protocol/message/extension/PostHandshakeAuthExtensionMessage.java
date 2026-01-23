/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.PostHandshakeAuthExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PostHandshakeAuthExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.PostHandshakeAuthExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PostHandshakeAuthExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "PostHandshakeAuth")
public class PostHandshakeAuthExtensionMessage extends ExtensionMessage {

    public PostHandshakeAuthExtensionMessage() {
        super(ExtensionType.POST_HANDSHAKE_AUTH);
    }

    @Override
    public PostHandshakeAuthExtensionParser getParser(TlsContext context, InputStream stream) {
        return new PostHandshakeAuthExtensionParser(stream, context);
    }

    @Override
    public PostHandshakeAuthExtensionPreparator getPreparator(TlsContext context) {
        return new PostHandshakeAuthExtensionPreparator(context.getChooser(), this);
    }

    @Override
    public PostHandshakeAuthExtensionSerializer getSerializer(TlsContext context) {
        return new PostHandshakeAuthExtensionSerializer(this);
    }

    @Override
    public PostHandshakeAuthExtensionHandler getHandler(TlsContext context) {
        return new PostHandshakeAuthExtensionHandler(context);
    }

}

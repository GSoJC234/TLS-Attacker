/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.AuthzDataFormat;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerAuthzExtensionMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;

public class ServerAuthzExtensionHandler extends ExtensionHandler<ServerAuthzExtensionMessage> {

    public ServerAuthzExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(ServerAuthzExtensionMessage message) {
        tlsContext
            .setServerAuthzDataFormatList(AuthzDataFormat.byteArrayToList(message.getAuthzFormatList().getValue()));
    }

}

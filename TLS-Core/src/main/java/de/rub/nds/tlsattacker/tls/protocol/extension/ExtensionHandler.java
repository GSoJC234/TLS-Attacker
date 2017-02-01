/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.extension;

import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @param <Message>
 */
public abstract class ExtensionHandler<Message extends ExtensionMessage> {

    ExtensionMessage extensionMessage;

    public abstract void prepareExtension(TlsContext context);

    public abstract int parseExtension(byte[] message, int pointer);

    public ExtensionMessage getExtensionMessage() {
        return extensionMessage;
    }

    public void setExtensionMessage(Message extensionMessage) {
        this.extensionMessage = extensionMessage;
    }
}

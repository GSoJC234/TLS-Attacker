/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.KeyShareExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.List;
import org.junit.jupiter.api.Test;

public class AddHRRKeyShareActionTest {

    @Test
    public void generatedExtensionRetainsSelectedGroupForContextAdjustment() {
        AddHRRKeyShareAction action = new AddHRRKeyShareAction();
        action.setExtensions(List.of(NamedGroup.SECP521R1));

        KeyShareExtensionMessage message =
                (KeyShareExtensionMessage)
                        action.generateExtensionMessages(ConnectionEndType.SERVER, null);

        assertArrayEquals(ExtensionType.KEY_SHARE.getValue(), message.getExtensionType().getValue());
        assertTrue(message.isRetryRequestMode());
        assertArrayEquals(NamedGroup.SECP521R1.getValue(), message.getKeyShareListBytes().getValue());
        assertEquals(1, message.getKeyShareList().size());
        assertSame(NamedGroup.SECP521R1, message.getKeyShareList().get(0).getGroupConfig());

        TlsContext context = new State().getTlsContext();
        new KeyShareExtensionHandler(context).adjustContext(message);

        assertSame(NamedGroup.SECP521R1, context.getSelectedGroup());
    }
}

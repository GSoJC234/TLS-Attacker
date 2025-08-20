/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.exception.PreparationException;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKBinder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKIdentity;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.protocol.serializer.ClientHelloSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PSKBinderSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PSKIdentitySerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PreSharedKeyExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

@XmlRootElement(name = "AddSHPreSharedKeyAction")
public class AddSHPreSharedKeyAction extends AddExtensionAction<SessionTicket> {
    public AddSHPreSharedKeyAction() {
        super();
    }

    public AddSHPreSharedKeyAction(String alias) {
        super(alias);
    }

    public AddSHPreSharedKeyAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
    }

    public AddSHPreSharedKeyAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public AddSHPreSharedKeyAction(String alias, List<ProtocolMessage> container) {
        super(alias, container);
    }


    @Override
    protected ExtensionMessage generateExtensionMessages(ConnectionEndType endType, State state) {
        PreSharedKeyExtensionMessage message = new PreSharedKeyExtensionMessage();
        message.setExtensionType(ExtensionType.PRE_SHARED_KEY.getValue());

        List<SessionTicket> sessionTickets = extension_container;
        SessionTicket ticket = sessionTickets.get(0);
        message.setSelectedIdentity(0);

        PreSharedKeyExtensionSerializer serializer =
                new PreSharedKeyExtensionSerializer(message, endType);
        message.setExtensionContent(serializer.serializeExtensionContent());
        message.setExtensionLength(message.getExtensionContent().getValue().length);
        message.setExtensionBytes(serializer.serialize());

        return message;
    }

}

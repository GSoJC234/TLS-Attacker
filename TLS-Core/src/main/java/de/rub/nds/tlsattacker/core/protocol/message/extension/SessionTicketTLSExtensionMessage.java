/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.StructuredLogValueBuilder;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SessionTicketTLSExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SessionTicketTLSExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SessionTicketTLSExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SessionTicketTLSExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** This extension is defined in RFC4507 */
@XmlRootElement(name = "SessionTicketTLSExtension")
public class SessionTicketTLSExtensionMessage extends ExtensionMessage {

    @HoldsModifiableVariable private SessionTicket sessionTicket;

    /** Constructor */
    public SessionTicketTLSExtensionMessage() {
        super(ExtensionType.SESSION_TICKET);
        sessionTicket = new SessionTicket();
    }

    public SessionTicket getSessionTicket() {
        return sessionTicket;
    }

    public void setSessionTicket(SessionTicket sessionTicket) {
        this.sessionTicket = sessionTicket;
    }

    @Override
    protected void addStructuredLogFields(StructuredLogValueBuilder builder) {
        super.addStructuredLogFields(builder);
        if (sessionTicket == null) {
            builder.add("ticket", null);
            return;
        }
        builder.add(
                "ticket",
                new StructuredLogValueBuilder()
                        .addHex(
                                "keyName",
                                sessionTicket.getKeyName() == null
                                        ? null
                                        : sessionTicket.getKeyName().getValue())
                        .addHex(
                                "iv",
                                sessionTicket.getIV() == null
                                        ? null
                                        : sessionTicket.getIV().getValue())
                        .add(
                                "encryptedStateLength",
                                sessionTicket.getEncryptedStateLength() == null
                                        ? null
                                        : sessionTicket.getEncryptedStateLength().getValue())
                        .addHex(
                                "encryptedState",
                                sessionTicket.getEncryptedState() == null
                                        ? null
                                        : sessionTicket.getEncryptedState().getValue())
                        .addHex(
                                "mac",
                                sessionTicket.getMAC() == null
                                        ? null
                                        : sessionTicket.getMAC().getValue())
                        .add(
                                "identityLength",
                                sessionTicket.getIdentityLength() == null
                                        ? null
                                        : sessionTicket.getIdentityLength().getValue())
                        .addHex(
                                "identity",
                                sessionTicket.getIdentity() == null
                                        ? null
                                        : sessionTicket.getIdentity().getValue())
                        .addHex(
                                "ticketAgeAdd",
                                sessionTicket.getTicketAgeAdd() == null
                                        ? null
                                        : sessionTicket.getTicketAgeAdd().getValue())
                        .add(
                                "ticketNonceLength",
                                sessionTicket.getTicketNonceLength() == null
                                        ? null
                                        : sessionTicket.getTicketNonceLength().getValue())
                        .addHex(
                                "ticketNonce",
                                sessionTicket.getTicketNonce() == null
                                        ? null
                                        : sessionTicket.getTicketNonce().getValue()));
    }

    @Override
    public SessionTicketTLSExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new SessionTicketTLSExtensionParser(stream, tlsContext.getConfig(), tlsContext);
    }

    @Override
    public SessionTicketTLSExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new SessionTicketTLSExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public SessionTicketTLSExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new SessionTicketTLSExtensionSerializer(this);
    }

    @Override
    public SessionTicketTLSExtensionHandler getHandler(TlsContext tlsContext) {
        return new SessionTicketTLSExtensionHandler(tlsContext);
    }

    @Override
    public String toCompactString() {
        return super.toCompactString();
    }
}

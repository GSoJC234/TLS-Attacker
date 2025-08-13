/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.NewSessionTicketSerializer;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildNewSessionTicket")
public class BuildNewSessionTicket extends ConnectionBoundAction  {

    @XmlTransient protected List<ProtocolMessage> container = null;
    @XmlTransient protected List<SessionTicket> ticketList = null;

    public BuildNewSessionTicket() {
        super();
    }

    public BuildNewSessionTicket(String alias) {
        super(alias);
    }

    public BuildNewSessionTicket(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildNewSessionTicket(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildNewSessionTicket(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setTicket(List<SessionTicket> ticketList) {
        this.ticketList = ticketList;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        SessionTicket ticketOrigin = this.ticketList.get(0);

        NewSessionTicketMessage message = new NewSessionTicketMessage();
        message.setShouldPrepareDefault(false);

        message.setType(HandshakeMessageType.NEW_SESSION_TICKET.getValue());
        message.setTicketLifetimeHint(86400);

        byte[] origNonce = ticketOrigin.getTicketNonce().getValue();
        int nonceLen = (origNonce != null) ? Math.min(origNonce.length, 8) : 4;
        byte[] nonce = new byte[nonceLen];
        if (origNonce != null && origNonce.length >= nonceLen) {
            System.arraycopy(origNonce, 0, nonce, 0, nonceLen);
        } else {
            new java.security.SecureRandom().nextBytes(nonce);
        }

        byte[] identity = ticketOrigin.getIdentity().getValue();
        if (identity == null || identity.length == 0) {
            identity = new byte[] { 0x00 }; // 최소 1바이트
        }

        SessionTicket ticket = message.getTicket();
        ticket.setTicketNonce(nonce);
        ticket.setTicketNonceLength(nonce.length);
        ticket.setIdentity(identity);
        ticket.setIdentityLength(identity.length);
        ticket.setTicketAgeAdd(ticketOrigin.getTicketAgeAdd());

        message.setExtensionBytes(new byte[0]);
        message.setExtensionsLength(0);

        NewSessionTicketSerializer serializer =
                new NewSessionTicketSerializer(message, ProtocolVersion.TLS13);
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        message.setCompleteResultingMessage(serializer.serialize());

        container.add(message);
        setExecuted(true);
    }

    @Override
    public void reset() {

    }

    @Override
    public boolean executedAsPlanned() {
        return true;
    }
}

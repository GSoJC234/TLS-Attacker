/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.Set;

/** Sets a deterministic elapsed age for the given PSK session ticket. */
@XmlRootElement(name = "SetTicketAgeMillisAction")
public class SetTicketAgeMillisAction extends ConnectionBoundAction {

    @XmlTransient private List<SessionTicket> sessionTickets;
    private long ticketAgeMillis;

    public SetTicketAgeMillisAction() {
        super();
    }

    public SetTicketAgeMillisAction(String alias) {
        super(alias);
    }

    public SetTicketAgeMillisAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public SetTicketAgeMillisAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public void setSessionTickets(List<SessionTicket> sessionTickets) {
        this.sessionTickets = sessionTickets;
    }

    public void setTicketAgeMillis(long ticketAgeMillis) {
        if (ticketAgeMillis < 0) {
            throw new IllegalArgumentException("Ticket age in milliseconds must not be negative");
        }
        this.ticketAgeMillis = ticketAgeMillis;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        if (sessionTickets == null || sessionTickets.isEmpty()) {
            throw new ActionExecutionException("SetTicketAgeMillisAction requires a session ticket");
        }
        for (SessionTicket ticket : sessionTickets) {
            if (ticket == null) {
                throw new ActionExecutionException("SetTicketAgeMillisAction received a null session ticket");
            }
            ticket.setTicketAgeMillis(ticketAgeMillis);
        }
        setExecuted(true);
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}

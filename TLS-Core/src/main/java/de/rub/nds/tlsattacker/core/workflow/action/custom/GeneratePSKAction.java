/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Set;
import javax.crypto.Mac;

@XmlRootElement(name = "GeneratePSKAction")
public class GeneratePSKAction extends ConnectionBoundAction {

    @XmlTransient private List<PskSet> container = null;
    @XmlTransient private List<SessionTicket> ticketList = null;

    public GeneratePSKAction() {
        super();
    }

    public GeneratePSKAction(String alias) {
        super(alias);
    }

    public GeneratePSKAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public GeneratePSKAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public GeneratePSKAction(String alias, List<PskSet> container) {
        super(alias);
        this.container = container;
    }

    public void setSessionTicket(List<SessionTicket> ticketList){
        this.ticketList = ticketList;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());
        SessionTicket ticket = ticketList.get(0);

        PskSet pskSet = new PskSet();
        pskSet.setCipherSuite(tlsContext.getChooser().getSelectedCipherSuite());
        if(ticket.getTicketAgeAdd() != null){
            pskSet.setTicketAgeAdd(ticket.getTicketAgeAdd().getValue());
        }
        if (ticket.getIdentity() != null) {
            pskSet.setPreSharedKeyIdentity(ticket.getIdentity().getValue());
        }
        pskSet.setTicketAge(getTicketAge());
        if (ticket.getTicketNonce() != null) {
            pskSet.setTicketNonce(ticket.getTicketNonce().getValue());
        }
        // only derive PSK if client finished was already sent, because full handshake transcript is
        // required
        if (tlsContext.getActiveClientKeySetType() == Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS) {
            pskSet.setPreSharedKey(derivePsk(tlsContext, pskSet));
        }

        container.add(pskSet);
        setExecuted(true);
    }

    private String getTicketAge() {
        DateTimeFormatter dateTimeFormatter =
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
        LocalDateTime ticketDate = LocalDateTime.now();

        return ticketDate.format(dateTimeFormatter);
    }

    private byte[] derivePsk(TlsContext tlsContext, PskSet pskSet) {
        try {
            LOGGER.debug("Deriving PSK from current session");
            HKDFAlgorithm hkdfAlgorithm =
                    AlgorithmResolver.getHKDFAlgorithm(
                            tlsContext.getChooser().getSelectedCipherSuite());
            DigestAlgorithm digestAlgo =
                    AlgorithmResolver.getDigestAlgorithm(
                            tlsContext.getChooser().getSelectedProtocolVersion(),
                            tlsContext.getChooser().getSelectedCipherSuite());
            int macLength =
                    Mac.getInstance(hkdfAlgorithm.getMacAlgorithm().getJavaName()).getMacLength();
            byte[] resumptionMasterSecret =
                    HKDFunction.deriveSecret(
                            hkdfAlgorithm,
                            digestAlgo.getJavaName(),
                            tlsContext.getChooser().getMasterSecret(),
                            HKDFunction.RESUMPTION_MASTER_SECRET,
                            tlsContext.getDigest().getRawBytes());
            tlsContext.setResumptionMasterSecret(resumptionMasterSecret);
            LOGGER.debug("Derived ResumptionMasterSecret: {}", resumptionMasterSecret);
            LOGGER.debug(
                    "Handshake Transcript Raw Bytes: {}", tlsContext.getDigest().getRawBytes());
            byte[] psk =
                    HKDFunction.expandLabel(
                            hkdfAlgorithm,
                            resumptionMasterSecret,
                            HKDFunction.RESUMPTION,
                            pskSet.getTicketNonce(),
                            macLength);
            LOGGER.debug("New derived pre-shared-key: {}", psk);
            return psk;

        } catch (NoSuchAlgorithmException | CryptoException ex) {
            LOGGER.error("DigestAlgorithm for psk derivation unknown");
            return new byte[0];
        }
    }

    @Override
    public void reset() {

    }

    @Override
    public boolean executedAsPlanned() {
        return true;
    }
}

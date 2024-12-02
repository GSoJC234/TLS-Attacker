/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.preparator.cert.CertificateEntryPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.cert.CertificatePairSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

@XmlRootElement(name = "ChangeCertificateAction")
public class ChangeCertificateAction extends TlsAction {

    @XmlTransient private List<ProtocolMessage> container = null;
    @XmlTransient private List<CertificateEntry> before_entries = null;
    @XmlTransient private List<CertificateEntry> after_entries = null;

    public ChangeCertificateAction() {}

    public ChangeCertificateAction(
            List<ProtocolMessage> container,
            List<CertificateEntry> before_entries,
            List<CertificateEntry> after_entries) {
        this.container = container;
        this.before_entries = before_entries;
        this.after_entries = after_entries;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        ProtocolMessage message = container.get(0);
        if (message instanceof CertificateMessage) {
            CertificateMessage certificate_message = (CertificateMessage) message;
            certificate_message.getCertificateEntryList().removeAll(before_entries);
            certificate_message.getCertificateEntryList().addAll(after_entries);

            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            for (CertificateEntry entry : after_entries) {
                CertificateEntryPreparator preparator =
                        new CertificateEntryPreparator(state.getContext().getChooser(), entry);
                preparator.prepare();
                CertificatePairSerializer serializer =
                        new CertificatePairSerializer(entry, ProtocolVersion.TLS12);
                try {
                    stream.write(serializer.serialize());
                } catch (IOException ex) {
                    throw new ActionExecutionException(
                            "Could not write byte[] from CertificateEntry", ex);
                }
            }
            certificate_message.setCertificatesListBytes(stream.toByteArray());
            certificate_message.setCertificatesListLength(
                    certificate_message.getCertificatesListBytes().getValue().length);
            setExecuted(true);
        } else {
            throw new ActionExecutionException(
                    "Only certificate message can be changed!" + message);
        }
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    @Override
    public boolean executedAsPlanned() {
        return true;
    }
}

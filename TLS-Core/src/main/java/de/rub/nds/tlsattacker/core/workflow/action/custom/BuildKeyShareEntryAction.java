/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.KeyShareCalculator;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.math.BigInteger;
import java.util.List;

@XmlRootElement(name = "BuildKeyShareEntry")
public class BuildKeyShareEntryAction extends TlsAction {

    @XmlTransient private List<KeyShareEntry> keyshare_container;
    @XmlTransient private List<NamedGroup> namedGroup_container;
    @XmlTransient private List<byte[]> privateKey_container;

    public BuildKeyShareEntryAction() {
        super();
    }

    public BuildKeyShareEntryAction(List<KeyShareEntry> keyshare_container) {
        this.keyshare_container = keyshare_container;
    }

    public void setNamedGroup(List<NamedGroup> namedGroup_container) {
        this.namedGroup_container = namedGroup_container;
    }

    public void setPrivateKey(List<byte[]> privateKey_container) {
        this.privateKey_container = privateKey_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        byte[] privateKey = privateKey_container.get(0);
        NamedGroup namedGroup = namedGroup_container.get(0);

        KeyShareEntry entry = new KeyShareEntry();
        entry.setGroup(namedGroup.getValue());
        byte[] publicKey =
                KeyShareCalculator.createPublicKey(
                        namedGroup, new BigInteger(privateKey), ECPointFormat.UNCOMPRESSED);
        entry.setPublicKey(publicKey);
        entry.setPublicKeyLength(publicKey.length);

        keyshare_container.add(entry);
        setExecuted(true);
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

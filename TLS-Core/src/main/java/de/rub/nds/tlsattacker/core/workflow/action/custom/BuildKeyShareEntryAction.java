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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildKeyShareEntry")
public class BuildKeyShareEntryAction extends ConnectionBoundAction {

    @XmlTransient private List<KeyShareEntry> keyshare_container;
    @XmlTransient private List<NamedGroup> namedGroup_container;

    public BuildKeyShareEntryAction() {
        super();
    }

    public BuildKeyShareEntryAction(String alias) {
        super(alias);
    }

    public BuildKeyShareEntryAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildKeyShareEntryAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildKeyShareEntryAction(String alias, List<KeyShareEntry> keyshare_container) {
        super(alias);
        this.keyshare_container = keyshare_container;
    }

    public void setNamedGroup(List<NamedGroup> namedGroup_container) {
        this.namedGroup_container = namedGroup_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        NamedGroup namedGroup = namedGroup_container.get(0);
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());
        KeyShareEntry entry = new KeyShareEntry();
        entry.setGroup(namedGroup.getValue());
        byte[] publicKey =
                KeyShareCalculator.createPublicKey(
                        namedGroup,
                        tlsContext.getConfig().getDefaultKeySharePrivateKey(namedGroup),
                        ECPointFormat.UNCOMPRESSED);
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

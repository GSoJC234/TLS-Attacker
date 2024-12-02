/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "EncryptAction")
public class EncryptAction extends ConnectionBoundAction {

    @XmlTransient private List<Record> record_container;
    @XmlTransient private List<KeySet> keySet_container;

    public EncryptAction() {}

    public EncryptAction(String alias) {
        super(alias);
    }

    public EncryptAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public EncryptAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public void setRecord(List<Record> record_container) {
        this.record_container = record_container;
    }

    public void setKeySet(List<KeySet> ketSet_container) {
        this.keySet_container = ketSet_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        Record record = record_container.get(0);
        KeySet keyset = keySet_container.get(0);
        TlsContext context = state.getTlsContext(getConnectionAlias());

        RecordCipher cipher = RecordCipherFactory.getRecordCipher(context, keyset, true);
        try {
            cipher.encrypt(record);
            setExecuted(true);
        } catch (CryptoException e) {
            throw new RuntimeException(e);
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

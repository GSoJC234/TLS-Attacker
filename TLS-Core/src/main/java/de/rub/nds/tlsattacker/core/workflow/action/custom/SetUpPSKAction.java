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
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "SetUpPSKAction")
public class SetUpPSKAction extends ConnectionBoundAction {

    @XmlTransient protected List<PskSet> pskSetList = null;

    public SetUpPSKAction() {
        super();
    }

    public SetUpPSKAction(String alias) {
        super(alias);
    }

    public SetUpPSKAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public SetUpPSKAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public void setPSK(List<PskSet> pskSetList){
        this.pskSetList = pskSetList;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        state.getTlsContext(getConnectionAlias()).setPskSets(pskSetList);
        state.getTlsContext(getConnectionAlias()).setPsk(pskSetList.get(0).getPreSharedKey());
        state.getConfig().setUsePsk(true);
        state.getConfig().setPsk(pskSetList.get(0).getPreSharedKey());
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

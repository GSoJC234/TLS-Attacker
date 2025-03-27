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
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.ChangeCipherSpecSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildChangeCipherSpecAction")
public class BuildChangeCipherSpecAction extends ConnectionBoundAction {

    @XmlTransient protected List<ProtocolMessage> container = null;

    public BuildChangeCipherSpecAction() {
        super();
    }

    public BuildChangeCipherSpecAction(String alias) {
        super(alias);
    }

    public BuildChangeCipherSpecAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildChangeCipherSpecAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildChangeCipherSpecAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        ChangeCipherSpecMessage message = new ChangeCipherSpecMessage();
        message.setShouldPrepareDefault(false);

        message.setCcsProtocolType(new byte[] {1});

        ChangeCipherSpecSerializer serializer = new ChangeCipherSpecSerializer(message);
        message.setCompleteResultingMessage(serializer.serialize());

        container.add(message);
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

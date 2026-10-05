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
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.ApplicationMessageSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildApplicationDataAction")
public class BuildApplicationDataAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container;
    @XmlTransient private List<byte[]> payloadContainer;

    public BuildApplicationDataAction() {
        super();
    }

    public BuildApplicationDataAction(String alias) {
        super(alias);
    }

    public BuildApplicationDataAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildApplicationDataAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildApplicationDataAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setPayload(List<byte[]> payloadContainer) {
        this.payloadContainer = payloadContainer;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        if (container == null) {
            throw new ActionExecutionException("BuildApplicationDataAction: container is null");
        }
        if (payloadContainer == null || payloadContainer.isEmpty()) {
            throw new ActionExecutionException(
                    "BuildApplicationDataAction: payloadContainer is empty");
        }

        byte[] payload = payloadContainer.get(0);
        if (payload == null) {
            throw new ActionExecutionException("BuildApplicationDataAction: payload is null");
        }

        ApplicationMessage message = new ApplicationMessage(payload);
        message.setShouldPrepareDefault(false);
        message.setData(payload);

        ApplicationMessageSerializer serializer = new ApplicationMessageSerializer(message);
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
        return isExecuted();
    }
}

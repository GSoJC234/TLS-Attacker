/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.AlertSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildAlertAction")
public class BuildAlertAction extends ConnectionBoundAction {
    @XmlTransient protected List<ProtocolMessage> container = null;
    @XmlTransient private List<AlertLevel> alertLevel_container = null;
    @XmlTransient private List<AlertDescription> alertDescription_container = null;

    public BuildAlertAction() {
        super();
    }

    public BuildAlertAction(String alias) {
        super(alias);
    }

    public BuildAlertAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildAlertAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildAlertAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setAlertLevel(List<AlertLevel> alertLevel_container) {
        this.alertLevel_container = alertLevel_container;
    }

    public void setAlertDescription(List<AlertDescription> alertDescription_container) {
        this.alertDescription_container = alertDescription_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        AlertMessage message = new AlertMessage();
        message.setShouldPrepareDefault(false);

        message.setLevel(alertLevel_container.get(0).getValue());
        message.setDescription(alertDescription_container.get(0).getValue());
        message.setGoingToBeSent(true);

        AlertSerializer serializer = new AlertSerializer(message);
        message.setCompleteResultingMessage(serializer.serialize());

        container.add(message);
        System.out.println("Alert: " + message);
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

/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.exceptions.SkipActionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SimpleWorkflowExecutor extends WorkflowExecutor {
    private static final Logger LOGGER = LogManager.getLogger();

    public SimpleWorkflowExecutor(State state) {
        super(WorkflowExecutorType.DEFAULT, state);
    }

    @Override
    public void executeWorkflow() {
        state.getWorkflowTrace().reset();
        state.setStartTimestamp(System.currentTimeMillis());
        List<TlsAction> tlsActions = state.getWorkflowTrace().getTlsActions();
        for (TlsAction action : tlsActions) {
            try {
                action.normalize();
                this.executeAction(action, state);
            } catch (SkipActionException ex) {
                continue;
            }
        }
        if (state.getWorkflowTrace().executedAsPlanned()) {
            LOGGER.info("Workflow executed as planned.");
        } else {
            LOGGER.info("Workflow was not executed as planned.");
        }
    }
}

/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;

/**
 * Builds application data intended for TLS 1.3 early-data transmission.
 *
 * <p>The corresponding {@link de.rub.nds.tlsattacker.core.workflow.action.SendAction} must follow
 * this action. Sending the ClientHello with the early_data extension activates the early traffic
 * secret and write cipher; this action checks that state before preparing the payload.
 */
@XmlRootElement(name = "BuildEarlyDataAction")
public class BuildEarlyDataAction extends BuildApplicationDataAction {

    public BuildEarlyDataAction() {
        super();
    }

    public BuildEarlyDataAction(String alias, List<ProtocolMessage> container) {
        super(alias, container);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        var tlsContext = state.getTlsContext(getConnectionAlias());
        if (tlsContext.getChooser().getConnectionEndType() != ConnectionEndType.CLIENT) {
            throw new ActionExecutionException(
                    "BuildEarlyDataAction can only be used by a TLS client");
        }
        if (!tlsContext.isExtensionProposed(ExtensionType.EARLY_DATA)) {
            throw new ActionExecutionException(
                    "BuildEarlyDataAction requires a previously sent ClientHello with early_data");
        }
        if (tlsContext.getClientEarlyTrafficSecret() == null
                || tlsContext.getActiveClientKeySetType()
                        != Tls13KeySetType.EARLY_TRAFFIC_SECRETS) {
            throw new ActionExecutionException(
                    "BuildEarlyDataAction requires the client early traffic keys to be active");
        }

        super.execute(state);
    }
}

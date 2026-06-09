/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.FinishedSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

@XmlRootElement(name = "BuildFinishedAction")
public class BuildFinishedAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> container = null;
    @XmlTransient private List<HandshakeMessageType> type_container = null;
    @XmlTransient private List<byte[]> verify_data_container = null;

    public BuildFinishedAction() {
        super();
    }

    public BuildFinishedAction(String alias) {
        super(alias);
    }

    public BuildFinishedAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildFinishedAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public BuildFinishedAction(String alias, List<ProtocolMessage> container) {
        super(alias);
        this.container = container;
    }

    public void setVerifyData(List<byte[]> verify_data_container) {
        this.verify_data_container = verify_data_container;
    }

    public void setHandshakeType(List<HandshakeMessageType> type_container){
        this.type_container = type_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        FinishedMessage message = new FinishedMessage();
        message.setShouldPrepareDefault(false);
        if(type_container != null){
            message.setType(type_container.get(0).getValue());
        } else {
            message.setType(HandshakeMessageType.FINISHED.getValue());
        }
        if (verify_data_container != null) {
            message.setVerifyData(verify_data_container.get(0));
        } else {
            throw new ActionExecutionException("Could not set verify data.");
        }

        FinishedSerializer serializer = new FinishedSerializer(message);
        message.setMessageContent(serializer.serializeHandshakeMessageContent());
        message.setLength(message.getMessageContent().getValue().length);
        message.setCompleteResultingMessage(serializer.serialize());

        container.add(message);
        System.out.println("Finished: " + message);
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

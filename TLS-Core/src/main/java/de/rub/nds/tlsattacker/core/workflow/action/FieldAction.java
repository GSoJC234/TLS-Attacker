/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.function.Supplier;

@XmlRootElement(name = "FieldAction")
public class FieldAction<T> extends TlsAction {

    @XmlTransient private List<T> fieldContainer = null;
    @XmlTransient private Supplier<T> fieldSupplier = null;

    public FieldAction() {}

    public FieldAction(List<T> fieldContainer, Supplier<T> fieldSupplier) {
        this.fieldContainer = fieldContainer;
        this.fieldSupplier = fieldSupplier;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        T fieldValue = fieldSupplier.get();
        if (fieldValue != null) {
            fieldContainer.add(fieldValue);
            setExecuted(true);
        } else {
            fieldContainer.add(null);
        }
    }

    @Override
    public void reset() {
        fieldContainer.clear();
        setExecuted(false);
    }

    @Override
    public boolean executedAsPlanned() {
        return !fieldContainer.isEmpty();
    }
}

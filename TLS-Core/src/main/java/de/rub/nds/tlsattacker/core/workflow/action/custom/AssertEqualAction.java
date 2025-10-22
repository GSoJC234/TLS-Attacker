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
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.Objects;
import java.util.function.Supplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;

@XmlRootElement(name = "AssertEqualAction")
public class AssertEqualAction<T> extends TlsAction {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final Marker CERT_MARKER = MarkerManager.getMarker("CERT");


    @XmlTransient private Supplier<T> value1;
    @XmlTransient private Supplier<T> value2;
    private boolean comparisonResult;

    public AssertEqualAction() {}

    public AssertEqualAction(Supplier<T> value1, Supplier<T> value2) {
        this.value1 = value1;
        this.value2 = value2;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        comparisonResult = Objects.equals(value1.get(), value2.get());
        if (!comparisonResult) {
            LOGGER.info(CERT_MARKER,
                    "Assertion fails: "
                            + "expected -> "
                            + value1.get()
                            + ", actual -> "
                            + value2.get());
            throw new ActionExecutionException(
                    "Assertion fails: "
                            + "expected -> "
                            + value1.get()
                            + ", actual -> "
                            + value2.get());
        }
        LOGGER.info(CERT_MARKER,
                "Assertion pass: " + "expected -> " + value1.get() + ", actual -> " + value2.get());
        setExecuted(true);
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    @Override
    public boolean executedAsPlanned() {
        return comparisonResult;
    }
}

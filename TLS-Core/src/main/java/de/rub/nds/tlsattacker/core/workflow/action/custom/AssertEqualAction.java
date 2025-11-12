/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.record.compressor.compression.CompressionAlgorithm;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.ArrayList;
import java.util.Objects;
import java.util.function.Supplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;

@XmlRootElement(name = "AssertEqualAction")
public class AssertEqualAction<T> extends TlsAction {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final Marker VISUAL_MARKER = MarkerManager.getMarker("VISUAL");
    private static final Marker TEST_MARKER = MarkerManager.getMarker("TEST");


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
            LOGGER.info(VISUAL_MARKER,
                    "Assertion fails(" + getFieldName(value1.get()) + "): "
                            + "expected -> "
                            + ArrayConverter.bytesToHexString(getValueAsBytes(value1.get()))
                            + ", actual -> "
                            + ArrayConverter.bytesToHexString(getValueAsBytes(value2.get())));
            throw new ActionExecutionException(
                    "Assertion fails: "
                            + "expected -> "
                            + value1.get()
                            + ", actual -> "
                            + value2.get());
        }
        LOGGER.debug(TEST_MARKER,
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

    private String getFieldName(T value) {
        Object obj = ((ArrayList) value).get(0);
        if (obj instanceof ProtocolMessageType) {
            return "contentType";
        } else if (obj instanceof ProtocolVersion) {
            return "protocol";
        } else if (obj instanceof HandshakeMessageType) {
            return "handshakeType";
        } else if (obj instanceof CipherSuite) {
            return "cipherSuites";
        } else if (obj instanceof AlertDescription) {
            return "alertDesc";
        } else if (obj instanceof AlertLevel) {
            return "alertLev";
        } else if (obj instanceof CompressionAlgorithm) {
            return "compression";
        } else if (obj instanceof NamedGroup) {
            return "elliptic-curves";
        } else if (obj instanceof SignatureAndHashAlgorithm) {
            return "signature-algorithms";
        }
        return "";
    }

    private byte[] getValueAsBytes(T value) {
        Object obj = ((ArrayList) value).get(0);
        if (obj instanceof ProtocolMessageType) {
            return ((ProtocolMessageType) obj).getArrayValue();
        } else if (obj instanceof ProtocolVersion) {
            return ((ProtocolVersion) obj).getValue();
        } else if (obj instanceof HandshakeMessageType) {
            return ((HandshakeMessageType) obj).getArrayValue();
        } else if (obj instanceof CipherSuite) {
            return ((CipherSuite) obj).getByteValue();
        } else if (obj instanceof AlertDescription) {
            return ((AlertDescription) obj).getArrayValue();
        } else if (obj instanceof AlertLevel) {
            return ((AlertLevel) obj).getArrayValue();
        } else if (obj instanceof CompressionMethod) {
            return ((CompressionMethod) obj).getArrayValue();
        } else if (obj instanceof NamedGroup) {
            return ((NamedGroup) obj).getValue();
        } else if (obj instanceof SignatureAndHashAlgorithm) {
            return ((SignatureAndHashAlgorithm) obj).getByteValue();
        }
        return new byte[]{};
    }
}

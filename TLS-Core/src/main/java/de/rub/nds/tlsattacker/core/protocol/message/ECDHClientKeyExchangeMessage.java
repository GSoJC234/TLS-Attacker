/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.ECDHClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.ECDHClientComputations;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ECDHClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ECDHClientKeyExchangeSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;

@XmlRootElement(name = "ECDHClientKeyExchange")
public class ECDHClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    @HoldsModifiableVariable protected ECDHClientComputations computations;

    public ECDHClientKeyExchangeMessage() {
        super();
    }

    @Override
    public String toCompactString() {
        return this.toString();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n  handshakeType: ");
        if (getHandshakeMessageType() != null) {
            sb.append(ArrayConverter.bytesToHexString(new byte[]{getHandshakeMessageType().getValue()}));
        } else {
            sb.append("null");
        }
        sb.append("\n  handshakeLen: ");
        if (getLength() != null) {
            sb.append(ArrayConverter.bytesToHexString(getLength().getByteArray(3)));
        } else {
            sb.append("null");
        }
        sb.append(" computations: " + computations);
        return sb.toString();
    }

    @Override
    public ECDHClientComputations getComputations() {
        return computations;
    }

    @Override
    public ECDHClientKeyExchangeHandler getHandler(TlsContext tlsContext) {
        return new ECDHClientKeyExchangeHandler(tlsContext);
    }

    @Override
    public ECDHClientKeyExchangeParser getParser(TlsContext tlsContext, InputStream stream) {
        return new ECDHClientKeyExchangeParser(stream, tlsContext);
    }

    @Override
    public ECDHClientKeyExchangePreparator getPreparator(TlsContext tlsContext) {
        return new ECDHClientKeyExchangePreparator(tlsContext.getChooser(), this);
    }

    @Override
    public ECDHClientKeyExchangeSerializer getSerializer(TlsContext tlsContext) {
        return new ECDHClientKeyExchangeSerializer(this);
    }

    @Override
    public String toShortString() {
        return "ECDH_CKE";
    }

    @Override
    public void prepareComputations() {
        if (computations == null) {
            computations = new ECDHClientComputations();
        }
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (computations != null) {
            holders.add(computations);
        }
        return holders;
    }
}

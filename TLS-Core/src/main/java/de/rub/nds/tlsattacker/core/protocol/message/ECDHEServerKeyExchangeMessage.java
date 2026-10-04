/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.StructuredLogValueBuilder;
import de.rub.nds.tlsattacker.core.protocol.handler.ECDHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.ECDHEServerComputations;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ECDHEServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ECDHEServerKeyExchangeSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;

@XmlRootElement(name = "ECDHEServerKeyExchange")
public class ECDHEServerKeyExchangeMessage extends ServerKeyExchangeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    protected ModifiableByte curveType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    protected ModifiableByteArray namedGroup;

    protected ECDHEServerComputations computations;

    public ECDHEServerKeyExchangeMessage() {
        super();
    }

    public ModifiableByte getGroupType() {
        return curveType;
    }

    public void setCurveType(ModifiableByte curveType) {
        this.curveType = curveType;
    }

    public void setCurveType(byte curveType) {
        this.curveType = ModifiableVariableFactory.safelySetValue(this.curveType, curveType);
    }

    public ModifiableByteArray getNamedGroup() {
        return namedGroup;
    }

    public void setNamedGroup(ModifiableByteArray namedGroup) {
        this.namedGroup = namedGroup;
    }

    public void setNamedGroup(byte[] namedGroup) {
        this.namedGroup = ModifiableVariableFactory.safelySetValue(this.namedGroup, namedGroup);
    }

    @Override
    protected void addStructuredLogHandshakeBodyFields(StructuredLogValueBuilder builder) {
        super.addStructuredLogHandshakeBodyFields(builder);
        Byte curveTypeValue = curveType == null ? null : curveType.getValue();
        EllipticCurveType resolvedCurveType =
                curveTypeValue == null
                        ? null
                        : EllipticCurveType.getCurveType(curveTypeValue);
        if (resolvedCurveType != null) {
            builder.add("curveType", resolvedCurveType);
        } else {
            builder.addHex(
                    "curveType", curveTypeValue == null ? null : new byte[] {curveTypeValue});
        }
        byte[] groupBytes = namedGroup == null ? null : namedGroup.getValue();
        NamedGroup group = groupBytes == null ? null : NamedGroup.getNamedGroup(groupBytes);
        if (group != null) {
            builder.add("namedGroup", group);
        } else {
            builder.addHex("namedGroup", groupBytes);
        }
    }

    @Override
    public String toCompactString() {
        String value = "ECDHE_SERVER_KEY_EXCHANGE";
        return isRetransmission() ? value + " (ret.)" : value;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("ECDHEServerKeyExchangeMessage:");
        sb.append("\n  Curve Type: ");
        if (curveType != null && curveType.getValue() != null) {
            EllipticCurveType resolvedCurveType =
                    EllipticCurveType.getCurveType(curveType.getValue());
            sb.append(
                    resolvedCurveType == null
                            ? ArrayConverter.bytesToHexString(new byte[] {curveType.getValue()})
                            : resolvedCurveType);
        } else {
            sb.append("null");
        }
        sb.append("\n  Named Curve: ");
        if (namedGroup != null && namedGroup.getValue() != null) {
            NamedGroup resolvedGroup = NamedGroup.getNamedGroup(namedGroup.getValue());
            sb.append(
                    resolvedGroup == null
                            ? ArrayConverter.bytesToHexString(namedGroup.getValue())
                            : resolvedGroup);
        } else {
            sb.append("null");
        }
        sb.append("\n  Public Key: ");
        if (getPublicKey() != null && getPublicKey().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(getPublicKey().getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Signature and Hash Algorithm: ");
        if (this.getSignatureAndHashAlgorithm() != null
                && getSignatureAndHashAlgorithm().getValue() != null) {
            byte[] algorithmBytes = getSignatureAndHashAlgorithm().getValue();
            SignatureAndHashAlgorithm algorithm =
                    SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(algorithmBytes);
            sb.append(
                    algorithm == null
                            ? ArrayConverter.bytesToHexString(algorithmBytes)
                            : algorithm);
        } else {
            sb.append("null");
        }
        sb.append("\n  Signature: ");
        if (getSignature() != null && getSignature().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(getSignature().getValue()));
        } else {
            sb.append("null");
        }

        return sb.toString();
    }

    @Override
    public ECDHEServerComputations getKeyExchangeComputations() {
        return computations;
    }

    @Override
    public ECDHEServerKeyExchangeHandler getHandler(TlsContext tlsContext) {
        return new ECDHEServerKeyExchangeHandler(tlsContext);
    }

    @Override
    public ECDHEServerKeyExchangeParser getParser(TlsContext tlsContext, InputStream stream) {
        return new ECDHEServerKeyExchangeParser(stream, tlsContext);
    }

    @Override
    public ECDHEServerKeyExchangePreparator getPreparator(TlsContext tlsContext) {
        return new ECDHEServerKeyExchangePreparator(tlsContext.getChooser(), this);
    }

    @Override
    public ECDHEServerKeyExchangeSerializer getSerializer(TlsContext tlsContext) {
        return new ECDHEServerKeyExchangeSerializer(
                this, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public String toShortString() {
        return "ECDHE_SKE";
    }

    @Override
    public void prepareKeyExchangeComputations() {
        if (computations == null) {
            computations = new ECDHEServerComputations();
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

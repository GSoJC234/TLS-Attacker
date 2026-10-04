/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.StructuredLogValueBuilder;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.EllipticCurvesExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EllipticCurvesExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EllipticCurvesExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EllipticCurvesExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;

/**
 * This extension is defined in RFC-ietf-tls-rfc4492bis-17 Also known as "supported_groups"
 * extension
 */
@XmlRootElement(name = "EllipticCurves")
public class EllipticCurvesExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger supportedGroupsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray supportedGroups;

    public EllipticCurvesExtensionMessage() {
        super(ExtensionType.ELLIPTIC_CURVES);
    }

    public ModifiableInteger getSupportedGroupsLength() {
        return supportedGroupsLength;
    }

    public void setSupportedGroupsLength(int length) {
        this.supportedGroupsLength =
                ModifiableVariableFactory.safelySetValue(supportedGroupsLength, length);
    }

    public void setSupportedGroupsLength(ModifiableInteger supportedGroupsLength) {
        this.supportedGroupsLength = supportedGroupsLength;
    }

    public ModifiableByteArray getSupportedGroups() {
        return supportedGroups;
    }

    public void setSupportedGroups(byte[] array) {
        supportedGroups = ModifiableVariableFactory.safelySetValue(supportedGroups, array);
    }

    public void setSupportedGroups(ModifiableByteArray supportedGroups) {
        this.supportedGroups = supportedGroups;
    }

    @Override
    protected void addStructuredLogFields(StructuredLogValueBuilder builder) {
        super.addStructuredLogFields(builder);
        builder.add(
                "supportedGroupsLength",
                supportedGroupsLength == null ? null : supportedGroupsLength.getValue());
        byte[] values = supportedGroups == null ? null : supportedGroups.getValue();
        if (values == null) {
            builder.add("supportedGroups", null);
            return;
        }
        try {
            List<NamedGroup> groups = NamedGroup.namedGroupsFromByteArray(values);
            if (groups.size() * 2 == values.length) {
                builder.add("supportedGroups", groups);
                return;
            }
        } catch (RuntimeException ignored) {
            // Preserve malformed or unknown values as bytes.
        }
        builder.addHex("supportedGroups", values);
    }

    @Override
    public EllipticCurvesExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new EllipticCurvesExtensionParser(stream, tlsContext);
    }

    @Override
    public EllipticCurvesExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new EllipticCurvesExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public EllipticCurvesExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new EllipticCurvesExtensionSerializer(this);
    }

    @Override
    public EllipticCurvesExtensionHandler getHandler(TlsContext tlsContext) {
        return new EllipticCurvesExtensionHandler(tlsContext);
    }

    @Override
    public String toCompactString() {
        return super.toCompactString();
    }
}

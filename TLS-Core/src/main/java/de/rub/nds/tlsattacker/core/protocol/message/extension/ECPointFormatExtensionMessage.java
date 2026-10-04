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
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.StructuredLogValueBuilder;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ECPointFormatExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ECPointFormatExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ECPointFormatExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ECPointFormatExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/** This extension is defined in RFC-ietf-tls-rfc-4492bis-17 */
@XmlRootElement(name = "ECPointFormat")
public class ECPointFormatExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger pointFormatsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray pointFormats;

    public ECPointFormatExtensionMessage() {
        super(ExtensionType.EC_POINT_FORMATS);
    }

    public ModifiableByteArray getPointFormats() {
        return pointFormats;
    }

    public void setPointFormats(byte[] array) {
        this.pointFormats = ModifiableVariableFactory.safelySetValue(pointFormats, array);
    }

    public void setPointFormats(ModifiableByteArray pointFormats) {
        this.pointFormats = pointFormats;
    }

    public ModifiableInteger getPointFormatsLength() {
        return pointFormatsLength;
    }

    public void setPointFormatsLength(int length) {
        this.pointFormatsLength =
                ModifiableVariableFactory.safelySetValue(pointFormatsLength, length);
    }

    public void setPointFormatsLength(ModifiableInteger pointFormatsLength) {
        this.pointFormatsLength = pointFormatsLength;
    }

    @Override
    protected void addStructuredLogFields(StructuredLogValueBuilder builder) {
        super.addStructuredLogFields(builder);
        builder.add(
                "pointFormatsLength",
                pointFormatsLength == null ? null : pointFormatsLength.getValue());
        byte[] values = pointFormats == null ? null : pointFormats.getValue();
        if (values == null) {
            builder.add("pointFormats", null);
            return;
        }
        List<ECPointFormat> formats = new ArrayList<>();
        for (byte value : values) {
            ECPointFormat format = ECPointFormat.getECPointFormat(value);
            if (format == null) {
                builder.addHex("pointFormats", values);
                return;
            }
            formats.add(format);
        }
        builder.add("pointFormats", formats);
    }

    @Override
    public ECPointFormatExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new ECPointFormatExtensionParser(stream, tlsContext);
    }

    @Override
    public ECPointFormatExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new ECPointFormatExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public ECPointFormatExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new ECPointFormatExtensionSerializer(this);
    }

    @Override
    public ECPointFormatExtensionHandler getHandler(TlsContext tlsContext) {
        return new ECPointFormatExtensionHandler(tlsContext);
    }

    @Override
    public String toCompactString() {
        return super.toCompactString();
    }
}

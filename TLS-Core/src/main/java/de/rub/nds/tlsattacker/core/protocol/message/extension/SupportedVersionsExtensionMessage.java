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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.StructuredLogValueBuilder;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SupportedVersionsExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SupportedVersionsExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SupportedVersionsExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SupportedVersionsExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;

@XmlRootElement(name = "SupportedVersions")
public class SupportedVersionsExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger supportedVersionsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray supportedVersions;

    public SupportedVersionsExtensionMessage() {
        super(ExtensionType.SUPPORTED_VERSIONS);
    }

    public ModifiableInteger getSupportedVersionsLength() {
        return supportedVersionsLength;
    }

    public void setSupportedVersionsLength(int length) {
        this.supportedVersionsLength =
                ModifiableVariableFactory.safelySetValue(this.supportedVersionsLength, length);
    }

    public void setSupportedVersionsLength(ModifiableInteger supportedVersionsLength) {
        this.supportedVersionsLength = supportedVersionsLength;
    }

    public ModifiableByteArray getSupportedVersions() {
        return supportedVersions;
    }

    public void setSupportedVersions(byte[] array) {
        this.supportedVersions =
                ModifiableVariableFactory.safelySetValue(this.supportedVersions, array);
    }

    public void setSupportedVersions(ModifiableByteArray supportedVersions) {
        this.supportedVersions = supportedVersions;
    }

    @Override
    protected void addStructuredLogFields(StructuredLogValueBuilder builder) {
        super.addStructuredLogFields(builder);
        builder.add(
                "supportedVersionsLength",
                supportedVersionsLength == null ? null : supportedVersionsLength.getValue());
        byte[] values = supportedVersions == null ? null : supportedVersions.getValue();
        if (values == null) {
            builder.add("supportedVersions", null);
            return;
        }
        try {
            List<ProtocolVersion> versions = ProtocolVersion.getProtocolVersions(values);
            if (versions.size() * 2 == values.length) {
                builder.add("supportedVersions", versions);
                return;
            }
        } catch (RuntimeException ignored) {
            // Preserve malformed or unknown values as bytes.
        }
        builder.addHex("supportedVersions", values);
    }

    @Override
    public SupportedVersionsExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new SupportedVersionsExtensionParser(stream, tlsContext);
    }

    @Override
    public SupportedVersionsExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new SupportedVersionsExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public SupportedVersionsExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new SupportedVersionsExtensionSerializer(this);
    }

    @Override
    public SupportedVersionsExtensionHandler getHandler(TlsContext tlsContext) {
        return new SupportedVersionsExtensionHandler(tlsContext);
    }

    @Override
    public String toCompactString() {
        return super.toCompactString();
    }
}

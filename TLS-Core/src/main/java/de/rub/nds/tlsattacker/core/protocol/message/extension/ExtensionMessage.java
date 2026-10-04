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
import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.protocol.StructuredLogValueBuilder;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParametersExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import jakarta.xml.bind.annotation.XmlSeeAlso;
import java.io.InputStream;

@XmlSeeAlso({
    EncryptedServerNameIndicationExtensionMessage.class,
    ECPointFormatExtensionMessage.class,
    EllipticCurvesExtensionMessage.class,
    EllipticCurvesExtensionMessage.class,
    ExtendedMasterSecretExtensionMessage.class,
    GreaseExtensionMessage.class,
    HeartbeatExtensionMessage.class,
    MaxFragmentLengthExtensionMessage.class,
    RecordSizeLimitExtensionMessage.class,
    PaddingExtensionMessage.class,
    RenegotiationInfoExtensionMessage.class,
    ServerNameIndicationExtensionMessage.class,
    SessionTicketTLSExtensionMessage.class,
    SignatureAndHashAlgorithmsExtensionMessage.class,
    SignatureAlgorithmsCertExtensionMessage.class,
    SignedCertificateTimestampExtensionMessage.class,
    ExtendedRandomExtensionMessage.class,
    TokenBindingExtensionMessage.class,
    KeyShareExtensionMessage.class,
    SupportedVersionsExtensionMessage.class,
    AlpnExtensionMessage.class,
    CertificateStatusRequestExtensionMessage.class,
    CertificateStatusRequestV2ExtensionMessage.class,
    CertificateTypeExtensionMessage.class,
    ClientCertificateUrlExtensionMessage.class,
    ClientCertificateTypeExtensionMessage.class,
    ClientAuthzExtensionMessage.class,
    EncryptThenMacExtensionMessage.class,
    ServerAuthzExtensionMessage.class,
    ServerCertificateTypeExtensionMessage.class,
    SrtpExtensionMessage.class,
    TrustedCaIndicationExtensionMessage.class,
    TruncatedHmacExtensionMessage.class,
    EarlyDataExtensionMessage.class,
    PSKKeyExchangeModesExtensionMessage.class,
    PreSharedKeyExtensionMessage.class,
    UnknownExtensionMessage.class,
    PWDClearExtensionMessage.class,
    PWDProtectExtensionMessage.class,
    PasswordSaltExtensionMessage.class,
    CachedInfoExtensionMessage.class,
    CookieExtensionMessage.class,
    DtlsHandshakeMessageFragment.class,
    UserMappingExtensionMessage.class,
    SRPExtensionMessage.class,
    CachedInfoExtensionMessage.class,
    ConnectionIdExtensionMessage.class,
    CksExtensionMessage.class,
    QuicTransportParametersExtensionMessage.class,
    EncryptedClientHelloExtensionMessage.class
})
public abstract class ExtensionMessage extends ModifiableVariableHolder
        implements DataContainer<TlsContext> {

    protected ExtensionType extensionTypeConstant;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray extensionType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger extensionLength;

    @ModifiableVariableProperty private ModifiableByteArray extensionBytes;

    @ModifiableVariableProperty private ModifiableByteArray extensionContent;

    public ExtensionMessage() {}

    public ExtensionMessage(ExtensionType type) {
        this.extensionTypeConstant = type;
    }

    public ModifiableByteArray getExtensionType() {
        return extensionType;
    }

    public ModifiableInteger getExtensionLength() {
        return extensionLength;
    }

    public ModifiableByteArray getExtensionBytes() {
        return extensionBytes;
    }

    public void setExtensionType(byte[] array) {
        this.extensionType = ModifiableVariableFactory.safelySetValue(extensionType, array);
    }

    public void setExtensionType(ModifiableByteArray extensionType) {
        this.extensionType = extensionType;
    }

    public void setExtensionLength(int length) {
        this.extensionLength = ModifiableVariableFactory.safelySetValue(extensionLength, length);
    }

    public void setExtensionLength(ModifiableInteger extensionLength) {
        this.extensionLength = extensionLength;
    }

    public void setExtensionBytes(byte[] data) {
        this.extensionBytes = ModifiableVariableFactory.safelySetValue(extensionBytes, data);
    }

    public void setExtensionBytes(ModifiableByteArray extensionBytes) {
        this.extensionBytes = extensionBytes;
    }

    public ExtensionType getExtensionTypeConstant() {
        return extensionTypeConstant;
    }

    /** Returns this extension as a deterministic structured value for protocol trace logs. */
    public final StructuredLogValueBuilder toStructuredValue() {
        StructuredLogValueBuilder builder = new StructuredLogValueBuilder();
        byte[] encodedType = extensionType == null ? null : extensionType.getValue();
        ExtensionType resolvedType =
                encodedType == null
                        ? extensionTypeConstant
                        : ExtensionType.getExtensionType(encodedType);
        if (resolvedType != null && resolvedType != ExtensionType.UNKNOWN) {
            builder.add("extensionType", resolvedType);
        } else {
            builder.addHex("extensionType", encodedType);
        }
        builder.add(
                "extensionLength",
                extensionLength == null ? null : extensionLength.getValue());
        if (extensionContent != null) {
            builder.addHex("extensionContent", extensionContent.getValue());
        }
        addStructuredLogFields(builder);
        return builder;
    }

    public final String toStructuredString() {
        return toStructuredValue().toString();
    }

    /** Adds fields owned by a concrete extension class to its protocol trace value. */
    protected void addStructuredLogFields(StructuredLogValueBuilder builder) {}

    @Override
    public String toCompactString() {
        byte[] encodedType = extensionType == null ? null : extensionType.getValue();
        ExtensionType resolvedType =
                encodedType == null
                        ? extensionTypeConstant
                        : ExtensionType.getExtensionType(encodedType);
        if (resolvedType != null && resolvedType != ExtensionType.UNKNOWN) {
            return resolvedType.name();
        }
        return encodedType == null
                ? "UNKNOWN_EXTENSION"
                : "UNKNOWN_EXTENSION (" + ArrayConverter.bytesToHexString(encodedType) + ")";
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder(getClass().getSimpleName()).append(':');
        byte[] encodedType = extensionType == null ? null : extensionType.getValue();
        ExtensionType resolvedType = extensionTypeConstant;
        if (resolvedType == null && encodedType != null) {
            resolvedType = ExtensionType.getExtensionType(encodedType);
        }
        builder.append("\n    Extension Type: ").append(resolvedType);
        builder.append("\n    Encoded Type: ")
                .append(
                        encodedType == null
                                ? "null"
                                : ArrayConverter.bytesToHexString(encodedType));
        builder.append("\n    Extension Length: ")
                .append(extensionLength == null ? null : extensionLength.getValue());
        builder.append("\n    Extension Content: ")
                .append(
                        extensionContent == null || extensionContent.getValue() == null
                                ? "null"
                                : ArrayConverter.bytesToHexString(extensionContent.getValue()));
        return builder.toString();
    }

    public ModifiableByteArray getExtensionContent() {
        return extensionContent;
    }

    public void setExtensionContent(ModifiableByteArray extensionContent) {
        this.extensionContent = extensionContent;
    }

    public void setExtensionContent(byte[] content) {
        this.extensionContent =
                ModifiableVariableFactory.safelySetValue(this.extensionContent, content);
    }

    @Override
    public abstract ExtensionHandler<? extends ExtensionMessage> getHandler(TlsContext context);

    @Override
    public abstract ExtensionParser<? extends ExtensionMessage> getParser(
            TlsContext context, InputStream stream);

    @Override
    public abstract ExtensionPreparator<? extends ExtensionMessage> getPreparator(
            TlsContext context);

    @Override
    public abstract ExtensionSerializer<? extends ExtensionMessage> getSerializer(
            TlsContext context);
}

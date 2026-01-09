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
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.CertificateAuthoritiesExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CertificateAuthoritiesExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CertificateAuthoritiesExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CertificateAuthoritiesExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "CertificateAuthorities")
public class CertificateAuthoritiesExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger distinguishedNameLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray distinguishedNames;

    public CertificateAuthoritiesExtensionMessage() {
        super(ExtensionType.CERTIFICATE_AUTHORITIES);
    }

    public ModifiableInteger getDistinguishedNameLength() {
        return distinguishedNameLength;
    }

    public void setDistinguishedNameLength(int length) {
        this.distinguishedNameLength =
                ModifiableVariableFactory.safelySetValue(this.distinguishedNameLength, length);
    }

    public void setDistinguishedNameLength(ModifiableInteger certificateAuthorityLength) {
        this.distinguishedNameLength = certificateAuthorityLength;
    }

    public ModifiableByteArray getDistinguishedNames() {
        return distinguishedNames;
    }

    public void setDistinguishedNames(byte[] array) {
        this.distinguishedNames =
                ModifiableVariableFactory.safelySetValue(this.distinguishedNames, array);
    }

    public void setDistinguishedNames(ModifiableByteArray certificateAuthorities) {
        this.distinguishedNames = certificateAuthorities;
    }

    @Override
    public ExtensionHandler<? extends ExtensionMessage> getHandler(TlsContext tlsContext) {
        return new CertificateAuthoritiesExtensionHandler(tlsContext);
    }

    @Override
    public ExtensionParser<? extends ExtensionMessage> getParser(TlsContext tlsContext, InputStream stream) {
        return new CertificateAuthoritiesExtensionParser(stream, tlsContext);
    }

    @Override
    public ExtensionPreparator<? extends ExtensionMessage> getPreparator(TlsContext tlsContext) {
        return new CertificateAuthoritiesExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public ExtensionSerializer<? extends ExtensionMessage> getSerializer(TlsContext tlsContext) {
        return new CertificateAuthoritiesExtensionSerializer(this);
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n  certificate-authorities:\n: ");
        if (distinguishedNames != null && distinguishedNames.getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(distinguishedNames.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  certificate-authorities-len: ");
        if (getExtensionLength() != null) {
            sb.append(ArrayConverter.bytesToHexString(getExtensionLength().getByteArray(2)));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }
}

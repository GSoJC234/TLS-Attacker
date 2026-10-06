/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.UnknownExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.custom.SizeCalculator;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/** Adds the TLS 1.3 oid_filters extension to a CertificateRequest. */
@XmlRootElement(name = "AddOidFiltersAction")
public class AddOidFiltersAction extends AddExtensionAction<String> {

    @XmlTransient private List<byte[]> valuesDer;

    public AddOidFiltersAction() {
        super();
    }

    public AddOidFiltersAction(String alias, List<ProtocolMessage> container) {
        super(alias, container);
    }

    public void setValuesDer(List<byte[]> valuesDer) {
        this.valuesDer = valuesDer;
    }

    @Override
    protected ExtensionMessage generateExtensionMessages(ConnectionEndType endType, State state) {
        if (container == null || container.isEmpty()
                || !(container.get(0) instanceof CertificateRequestMessage)) {
            throw new IllegalArgumentException("oid_filters is only valid in CertificateRequest");
        }
        byte[] content = encodeFilters(extension_container, valuesDer);
        UnknownExtensionMessage message = new UnknownExtensionMessage();
        message.setExtensionType(ExtensionType.OID_FILTERS.getValue());
        message.setExtensionData(content);

        UnknownExtensionSerializer serializer = new UnknownExtensionSerializer(message);
        message.setExtensionContent(serializer.serializeExtensionContent());
        int defaultLength = message.getExtensionContent().getValue().length;
        int length = extension_len == null
                ? defaultLength
                : SizeCalculator.calculate(
                        extension_len.get(0), defaultLength, HandshakeByteLength.EXTENSION_LENGTH);
        message.setExtensionLength(length);
        message.setExtensionBytes(serializer.serialize());
        return message;
    }

    static byte[] encodeFilters(List<String> oids, List<byte[]> valuesDer) {
        if (oids == null || valuesDer == null || oids.size() != valuesDer.size()) {
            throw new IllegalArgumentException("OID and value lists must have the same size");
        }

        ByteArrayOutputStream filters = new ByteArrayOutputStream();
        for (int i = 0; i < oids.size(); i++) {
            byte[] oidDer;
            try {
                oidDer = new ASN1ObjectIdentifier(oids.get(i)).getEncoded("DER");
            } catch (IOException | IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid certificate extension OID: " + oids.get(i), e);
            }
            byte[] valueDer = valuesDer.get(i);
            if (oidDer.length == 0 || oidDer.length > 255) {
                throw new IllegalArgumentException("DER-encoded OID must fit in one length byte");
            }
            if (valueDer == null || valueDer.length > 65535) {
                throw new IllegalArgumentException("DER-encoded OID values must fit in two length bytes");
            }
            filters.write(oidDer.length);
            filters.write(oidDer, 0, oidDer.length);
            writeUint16(filters, valueDer.length);
            filters.write(valueDer, 0, valueDer.length);
            if (filters.size() > 65533) {
                throw new IllegalArgumentException("oid_filters extension content exceeds TLS length limit");
            }
        }

        ByteArrayOutputStream content = new ByteArrayOutputStream();
        writeUint16(content, filters.size());
        byte[] encodedFilters = filters.toByteArray();
        content.write(encodedFilters, 0, encodedFilters.length);
        return content.toByteArray();
    }

    private static void writeUint16(ByteArrayOutputStream output, int value) {
        output.write((value >>> 8) & 0xff);
        output.write(value & 0xff);
    }
}

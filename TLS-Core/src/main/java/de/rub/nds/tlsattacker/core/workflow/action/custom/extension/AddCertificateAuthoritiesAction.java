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
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateAuthoritiesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CertificateAuthoritiesExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.custom.SizeCalculator;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "AddCertificateAuthoritiesAction")
public class AddCertificateAuthoritiesAction extends AddExtensionAction<byte[]> {

    public AddCertificateAuthoritiesAction() {
        super();
    }

    public AddCertificateAuthoritiesAction(String alias) {
        super(alias);
    }

    public AddCertificateAuthoritiesAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
    }

    public AddCertificateAuthoritiesAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public AddCertificateAuthoritiesAction(String alias, List<ProtocolMessage> container) {
        super(alias, container);
    }

    @Override
    protected ExtensionMessage generateExtensionMessages(ConnectionEndType endType, State state) {
        CertificateAuthoritiesExtensionMessage message = new CertificateAuthoritiesExtensionMessage();
        message.setExtensionType(ExtensionType.CERTIFICATE_AUTHORITIES.getValue());

        message.setDistinguishedNames(extension_container.get(0));
        message.setDistinguishedNameLength(message.getDistinguishedNames().getValue().length);

        CertificateAuthoritiesExtensionSerializer serializer = new CertificateAuthoritiesExtensionSerializer(message);
        message.setExtensionContent(serializer.serializeExtensionContent());
        int defaultLen = message.getExtensionContent().getValue().length;
        int len = (extension_len == null) ? defaultLen
                : SizeCalculator.calculate(extension_len.get(0), defaultLen, HandshakeByteLength.EXTENSION_LENGTH);
        message.setExtensionLength(len);

        message.setExtensionBytes(serializer.serialize());
        return message;
    }
}

/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;

@XmlRootElement(name = "BuildHandshakeKeySetAction")
public class BuildHandshakeKeySetAction extends TlsAction {

    @XmlTransient private List<KeySet> keySets;
    @XmlTransient private List<ProtocolVersion> version_container;
    @XmlTransient private List<CipherSuite> cipher_suite_container;
    @XmlTransient private List<NamedGroup> namedGroup_container;
    @XmlTransient private List<byte[]> public_key_container;
    @XmlTransient private List<byte[]> private_key_container;

    private byte[] clientHandshakeTrafficSecret;
    private byte[] serverHandshakeTrafficSecret;

    public BuildHandshakeKeySetAction() {}

    public BuildHandshakeKeySetAction(List<KeySet> container) {}

    public void setProtocolVersion(List<ProtocolVersion> version_container) {
        this.version_container = version_container;
    }

    public void setSelectedCipherSuite(List<CipherSuite> cipher_suite_container) {
        this.cipher_suite_container = cipher_suite_container;
    }

    public void setNamedgroup(List<NamedGroup> namedgroup_container) {
        this.namedGroup_container = namedgroup_container;
    }

    public void setPublicKey(List<byte[]> public_key_container) {
        this.public_key_container = public_key_container;
    }

    public void setPrivateKey(List<byte[]> private_key_container) {
        this.private_key_container = private_key_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        ProtocolVersion version = version_container.get(0);
        CipherSuite cipherSuite = cipher_suite_container.get(0);
        NamedGroup namedGroup = namedGroup_container.get(0);
        byte[] publicKey = public_key_container.get(0);
        byte[] privateKey = private_key_container.get(0);
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    @Override
    public boolean executedAsPlanned() {
        return true;
    }
}

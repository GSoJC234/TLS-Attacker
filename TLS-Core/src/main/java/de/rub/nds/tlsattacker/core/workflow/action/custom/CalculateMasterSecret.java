/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.Arrays;
import java.util.List;

@XmlRootElement(name = "CalculateMasterSecret")
public class CalculateMasterSecret extends TlsAction {
    @XmlTransient private List<byte[]> container = null;
    @XmlTransient private List<byte[]> preMasterSecret_container = null;
    @XmlTransient private List<byte[]> clientRandom_container = null;
    @XmlTransient private List<byte[]> serverRandom_container = null;
    @XmlTransient private String clientAlias;
    @XmlTransient private String serverAlias;

    public CalculateMasterSecret() {
        super();
    }

    public CalculateMasterSecret(String clientAlias, String serverAlias, List<byte[]> container) {
        this.clientAlias = clientAlias;
        this.serverAlias = serverAlias;
        this.container = container;
    }

    public void setPreMasterSecret_container(List<byte[]> preMasterSecret_container) {
        this.preMasterSecret_container = preMasterSecret_container;
    }

    public void setClientRandom_container(List<byte[]> clientRandom_container) {
        this.clientRandom_container = clientRandom_container;
    }

    public void setServerRandom_container(List<byte[]> serverRandom_container) {
        this.serverRandom_container = serverRandom_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        byte[] clientRandom = clientRandom_container.get(0);
        byte[] serverRandom = serverRandom_container.get(0);
        byte[] preMasterSecret = preMasterSecret_container.get(0);

        TlsContext client = state.getTlsContext(clientAlias);
        TlsContext server = state.getTlsContext(serverAlias);

        byte[] masterSecret;
        try {
            masterSecret =
                    getMasterSecret(
                            preMasterSecret,
                            clientRandom,
                            serverRandom,
                            server.getSelectedProtocolVersion(),
                            server.getSelectedCipherSuite());
        } catch (CryptoException e) {
            throw new RuntimeException(e);
        }
        server.setMasterSecret(masterSecret);
        client.setMasterSecret(masterSecret);
        LOGGER.info("Master Secret: " + Arrays.toString(masterSecret));
        container.add(masterSecret);
    }

    private byte[] getMasterSecret(
            byte[] premasterSecret,
            byte[] clientRandom,
            byte[] serverRandom,
            ProtocolVersion version,
            CipherSuite cipherSuite)
            throws CryptoException {
        PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(version, cipherSuite);

        return PseudoRandomFunction.compute(
                prfAlgorithm,
                premasterSecret,
                PseudoRandomFunction.MASTER_SECRET_LABEL,
                ArrayConverter.concatenate(clientRandom, serverRandom),
                HandshakeByteLength.MASTER_SECRET);
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

/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import java.util.List;
import org.junit.jupiter.api.Test;

public class BuildCertificateVerifyActionTest {

    @Test
    public void usesWireAlgorithmForSigningByDefault() {
        BuildCertificateVerifyAction action = new BuildCertificateVerifyAction();

        assertEquals(
                SignatureAndHashAlgorithm.DSA_SHA256,
                action.resolveSigningAlgorithm(SignatureAndHashAlgorithm.DSA_SHA256));
    }

    @Test
    public void allowsSigningAlgorithmToDifferFromWireAlgorithm() {
        BuildCertificateVerifyAction action = new BuildCertificateVerifyAction();
        action.setSigningSignatureAndHashAlgorithmContainer(
                List.of(SignatureAndHashAlgorithm.RSA_SHA256));

        assertEquals(
                SignatureAndHashAlgorithm.RSA_SHA256,
                action.resolveSigningAlgorithm(SignatureAndHashAlgorithm.DSA_SHA256));
    }
}

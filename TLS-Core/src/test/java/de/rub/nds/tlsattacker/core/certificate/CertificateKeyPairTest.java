/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.certificate;

import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeEach;

public class CertificateKeyPairTest {

    private TlsContext tlsContext;

    @BeforeEach
    public void setUp() {
        tlsContext = new TlsContext();
    }

    @Test
    public void testAdjustInContext() {
        tlsContext.getConfig().setAutoAdjustSignatureAndHashAlgorithm(true);
        for (CertificateKeyPair certKeyPair : CertificateByteChooser.getInstance().getCertificateKeyPairList()) {
            certKeyPair.adjustInContext(tlsContext, ConnectionEndType.SERVER);
            switch (certKeyPair.getCertPublicKeyType()) {
                case RSA:
                    assertNotNull(tlsContext.getServerRSAPrivateKey());
                    assertNotNull(tlsContext.getServerRSAPublicKey());
                    break;
                case ECDH:
                case ECDSA:
                    assertNotNull(tlsContext.getServerEcPrivateKey());
                    assertNotNull(tlsContext.getServerEcPublicKey());
                    break;
                case DSS:
                    assertNotNull(tlsContext.getServerDsaPrivateKey());
                    assertNotNull(tlsContext.getServerDsaPublicKey());
                    break;
                default:
                    // skip for non-ephemeral
                    continue;
            }

            // ECDH can also be used for ECDH_ECDSA
            CertificateKeyType requiredKeyType = (certKeyPair.getCertPublicKeyType() == CertificateKeyType.ECDH)
                ? CertificateKeyType.ECDH_ECDSA : certKeyPair.getCertPublicKeyType();

            if (requiredKeyType != certKeyPair.getCertSignatureType()) {
                assertNotEquals(certKeyPair.getSignatureAndHashAlgorithm().getSignatureAlgorithm(),
                    tlsContext.getSelectedSignatureAndHashAlgorithm().getSignatureAlgorithm(),
                    "Certificate's SignatureAndHashAlgorithm and selected SignatureAndHashAlgorithm of the session must not be equal for CertificateKeyType mismatch");
            }

            assertEquals(requiredKeyType, tlsContext.getSelectedSignatureAndHashAlgorithm().getSignatureAlgorithm()
                .getRequiredCertificateKeyType(), "Signature scheme must match public key type");
        }
    }

}

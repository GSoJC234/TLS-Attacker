/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.GOSTClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;

public class GOST12ClientKeyExchangePreparator extends GOSTClientKeyExchangePreparator {

    public GOST12ClientKeyExchangePreparator(Chooser chooser, GOSTClientKeyExchangeMessage msg) {
        super(chooser, msg);
    }

    @Override
    protected String getKeyAgreementAlgorithm() {
        return "ECGOST3410-2012-256";
    }

    @Override
    protected String getKeyPairGeneratorAlgorithm() {
        return "ECGOST3410-2012";
    }

    @Override
    protected ASN1ObjectIdentifier getEncryptionParameters() {
        return RosstandartObjectIdentifiers.id_tc26_gost_28147_param_Z;
    }
}

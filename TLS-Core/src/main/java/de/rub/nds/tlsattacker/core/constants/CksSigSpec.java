/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import java.util.HashMap;
import java.util.Map;

/** Certificate Key Selection values used by the X9.146 CKS extension. */
public enum CksSigSpec {
    NATIVE((byte) 0x01),
    ALTERNATIVE((byte) 0x02),
    BOTH((byte) 0x03),
    EXTERNAL((byte) 0x04);

    private final byte value;

    private static final Map<Byte, CksSigSpec> MAP;

    static {
        MAP = new HashMap<>();
        for (CksSigSpec spec : CksSigSpec.values()) {
            MAP.put(spec.value, spec);
        }
    }

    private CksSigSpec(byte value) {
        this.value = value;
    }

    public static CksSigSpec getCksSigSpec(byte value) {
        return MAP.get(value);
    }

    public byte getValue() {
        return value;
    }
}

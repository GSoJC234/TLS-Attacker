/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

public class SizeCalculator {

    public static Integer calculate(Integer category, Integer defaultSize, Integer handshakeByteLength) {
        if (category == 1) {
            return defaultSize;
        } else if (category == 2) {
            // smaller case
            return defaultSize - handshakeByteLength;
        } else if (category == 3) {
            // larger case
            return defaultSize + handshakeByteLength;
        } else if (category == 4) {
            // minimum size
            return 0;
        } else if (category == 5) {
            // maximum size
            switch (handshakeByteLength) {
                case 1: return 255;
                case 2: return 65535;
                case 3: return 16777215;
                default: throw new RuntimeException("Unknown handshake byte length: " + handshakeByteLength);
            }
        } else {
            throw new RuntimeException("Unknown category: " + category);
        }
    }
}

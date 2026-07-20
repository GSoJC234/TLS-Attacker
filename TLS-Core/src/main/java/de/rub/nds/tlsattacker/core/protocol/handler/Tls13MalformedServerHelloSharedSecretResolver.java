/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import java.util.List;
import java.util.Locale;

final class Tls13MalformedServerHelloSharedSecretResolver {

    private Tls13MalformedServerHelloSharedSecretResolver() {}

    static byte[] resolveMissingKeyShareSharedSecret(
            TlsContext tlsContext, boolean serverHelloHasSelectedPsk) {
        if (tlsContext == null) {
            return null;
        }

        Config config = tlsContext.getConfig();
        if (config == null || !isWolfSsl(config)) {
            return null;
        }

        String runtimePlatform = normalize(config.getTargetRuntimePlatform());

        if (isWolfSsl582(config)) {
            if (serverHelloHasSelectedPsk
                    && "linux-amd64".equals(runtimePlatform)
                    && requiresDhePsk(tlsContext)
                    && clientOfferedKeyShare(tlsContext, NamedGroup.SECP256R1)) {
                // Before cd55fe613, onlyPskDheKe did not reject a selected-PSK ServerHello
                // without key_share. In this P-256 PSK-DHE path the affected wolfSSL 5.8.2
                // client consumes its 32-byte all-zero pending ECDHE buffer.
                return new byte[32];
            }
            return null;
        }

        if (serverHelloHasSelectedPsk) {
            return null;
        }

        if (isWolfSsl584(config)) {
            if ("linux-amd64".equals(runtimePlatform)
                    && tlsContext.isHelloRetryRequestProcessed()
                    && tlsContext.getSelectedGroup() == NamedGroup.SECP521R1) {
                // After an HRR selected P-521, the affected wolfSSL 5.8.4 path retains the
                // named group while accepting a final ServerHello without key_share. Its
                // configured ENCRYPT_LEN buffer becomes the 578-byte all-zero DHE input.
                return new byte[578];
            }
            return null;
        }

        if (!isWolfSsl560(config)) {
            return null;
        }

        if ("linux-amd64".equals(runtimePlatform)
                && tlsContext.isHelloRetryRequestProcessed()
                && tlsContext.getSelectedGroup() == NamedGroup.SECP521R1) {
            // With PSK disabled, the affected wolfSSL 5.6.0 client accepts a final
            // ServerHello without key_share after an HRR selected P-521. Its fixed
            // 512-byte pending ECDHE buffer becomes the all-zero DHE input.
            return new byte[512];
        }

        String executionMode = normalize(config.getTargetExecutionMode());
        String buildProfile = normalize(config.getTargetBuildProfile());
        if ("local".equals(executionMode)
                && "darwin-arm64".equals(runtimePlatform)
                && "local-forward-secrecy".equals(buildProfile)) {
            return new byte[384];
        }

        throw unresolved(config, false);
    }

    private static boolean requiresDhePsk(TlsContext tlsContext) {
        List<PskKeyExchangeMode> modes = tlsContext.getClientPskKeyExchangeModes();
        return modes != null
                && modes.contains(PskKeyExchangeMode.PSK_DHE_KE)
                && !modes.contains(PskKeyExchangeMode.PSK_KE);
    }

    private static boolean clientOfferedKeyShare(TlsContext tlsContext, NamedGroup group) {
        List<KeyShareStoreEntry> keyShares = tlsContext.getClientKeyShareStoreEntryList();
        return keyShares != null
                && keyShares.stream().anyMatch(entry -> entry != null && entry.getGroup() == group);
    }

    private static IllegalStateException unresolved(Config config, boolean selectedPsk) {
        return new IllegalStateException(
                "target_implementation_model_unresolved: wolfSSL "
                        + normalize(config.getTargetLibraryVersion())
                        + " malformed TLS 1.3 ServerHello without key_share"
                        + (selectedPsk ? " and with selected pre_shared_key " : " or selected pre_shared_key ")
                        + "requires matching target runtime and protocol state");
    }

    private static boolean isWolfSsl(Config config) {
        return "wolfssl".equals(normalize(config.getTargetLibraryName()));
    }

    private static boolean isWolfSsl560(Config config) {
        return "wolfssl".equals(normalize(config.getTargetLibraryName()))
                && "5.6.0".equals(normalize(config.getTargetLibraryVersion()));
    }

    private static boolean isWolfSsl582(Config config) {
        return "5.8.2".equals(normalize(config.getTargetLibraryVersion()));
    }

    private static boolean isWolfSsl584(Config config) {
        return "5.8.4".equals(normalize(config.getTargetLibraryVersion()));
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}

/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.UnknownCipherSuiteException;
import java.util.*;

public enum CipherSuite {
    TLS_NULL_WITH_NULL_NULL(0x00),
    TLS_RSA_WITH_NULL_MD5(0x01),
    TLS_RSA_WITH_NULL_SHA(0x02),
    TLS_RSA_EXPORT_WITH_RC4_40_MD5(0x03),
    TLS_RSA_WITH_RC4_128_MD5(0x04),
    TLS_RSA_WITH_RC4_128_SHA(0x05),
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5(0x06),
    TLS_RSA_WITH_IDEA_CBC_SHA(0x07),
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA(0x08),
    TLS_RSA_WITH_DES_CBC_SHA(0x09),
    TLS_RSA_WITH_3DES_EDE_CBC_SHA(0x0A),
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA(0x0B),
    TLS_DH_DSS_WITH_DES_CBC_SHA(0x0C),
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA(0x0D),
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA(0x0E),
    TLS_DH_RSA_WITH_DES_CBC_SHA(0x0F),
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA(0x10),
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA(0x11),
    TLS_DHE_DSS_WITH_DES_CBC_SHA(0x12),
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA(0x13),
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA(0x14),
    TLS_DHE_RSA_WITH_DES_CBC_SHA(0x15),
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA(0x16),
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5(0x17),
    TLS_DH_anon_WITH_RC4_128_MD5(0x18),
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA(0x19),
    TLS_DH_anon_WITH_DES_CBC_SHA(0x1A),
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA(0x1B),
    SSL_FORTEZZA_KEA_WITH_NULL_SHA(0x1C),
    SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA(0x1D),
    TLS_KRB5_WITH_DES_CBC_SHA(0x1E), // TODO this cipher suite clashes with
    // SSL_FORTEZZA_KEA_WITH_RC4_128_SHA
    TLS_KRB5_WITH_3DES_EDE_CBC_SHA(0x1F),
    TLS_KRB5_WITH_RC4_128_SHA(0x20),
    TLS_KRB5_WITH_IDEA_CBC_SHA(0x21),
    TLS_KRB5_WITH_DES_CBC_MD5(0x22),
    TLS_KRB5_WITH_3DES_EDE_CBC_MD5(0x23),
    TLS_KRB5_WITH_RC4_128_MD5(0x24),
    TLS_KRB5_WITH_IDEA_CBC_MD5(0x25),
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA(0x26),
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA(0x27),
    TLS_KRB5_EXPORT_WITH_RC4_40_SHA(0x28),
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5(0x29),
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5(0x2A),
    TLS_KRB5_EXPORT_WITH_RC4_40_MD5(0x2B),
    TLS_PSK_WITH_NULL_SHA(0x2C),
    TLS_DHE_PSK_WITH_NULL_SHA(0x2D),
    TLS_RSA_PSK_WITH_NULL_SHA(0x2E),
    TLS_RSA_WITH_AES_128_CBC_SHA(0x2F),
    TLS_DH_DSS_WITH_AES_128_CBC_SHA(0x30),
    TLS_DH_RSA_WITH_AES_128_CBC_SHA(0x31),
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA(0x32),
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA(0x33),
    TLS_DH_anon_WITH_AES_128_CBC_SHA(0x34),
    TLS_RSA_WITH_AES_256_CBC_SHA(0x35),
    TLS_DH_DSS_WITH_AES_256_CBC_SHA(0x36),
    TLS_DH_RSA_WITH_AES_256_CBC_SHA(0x37),
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA(0x38),
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA(0x39),
    TLS_DH_anon_WITH_AES_256_CBC_SHA(0x3A),
    TLS_RSA_WITH_NULL_SHA256(0x3B),
    TLS_RSA_WITH_AES_128_CBC_SHA256(0x3C),
    TLS_RSA_WITH_AES_256_CBC_SHA256(0x3D),
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256(0x3E),
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256(0x3F),
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256(0x40),
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA(0x41),
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA(0x42),
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA(0x43),
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA(0x44),
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA(0x45),
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA(0x46),
    UNOFFICIAL_TLS_ECDH_ECDSA_WITH_NULL_SHA(0x47),
    UNOFFICIAL_TLS_ECDH_ECDSA_WITH_RC4_128_SHA(0x48),
    UNOFFICIAL_TLS_ECDH_ECDSA_WITH_DES_CBC_SHA(0X49),
    UNOFFICIAL_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA(0X4A),
    UNOFFICIAL_TLS_ECDH_ECNRA_WITH_NULL_SHA(0x4B),
    UNOFFICIAL_TLS_ECDH_ECNRA_WITH_RC4_128_SHA(0x4C),
    UNOFFICIAL_TLS_ECDH_ECNRA_WITH_DES_CBC_SHA(0x4D),
    UNOFFICIAL_TLS_ECDH_ECNRA_WITH_3DES_EDE_CBC_SHA(0x4E),
    UNOFFICIAL_TLS_ECMQV_ECDSA_WITH_NULL_SHA(0x4F),
    UNOFFICIAL_TLS_ECMQV_ECDSA_WITH_RC4_128_SHA(0x50),
    UNOFFICIAL_TLS_ECMQV_ECDSA_WITH_DES_CBC_SHA(0x51),
    UNOFFICIAL_TLS_ECMQV_ECDSA_WITH_3DES_EDE_CBC_SHA(0x52),
    UNOFFICIAL_TLS_ECMQV_ECNRA_WITH_NULL_SHA(0x53),
    UNOFFICIAL_TLS_ECMQV_ECNRA_WITH_RC4_128_SHA(0x54),
    UNOFFICIAL_TLS_ECMQV_ECNRA_WITH_DES_CBC_SHA(0x55),
    UNOFFICIAL_TLS_ECMQV_ECNRA_WITH_3DES_EDE_CBC_SHA(0x56),
    UNOFFICIAL_TLS_ECDH_anon_WITH_NULL_SHA(0x57),
    UNOFFICIAL_TLS_ECDH_anon_WITH_RC4_128_SHA(0x58),
    UNOFFICIAL_TLS_ECDH_anon_WITH_DES_CBC_SHA(0x59),
    UNOFFICIAL_TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA(0x5A),
    UNOFFICIAL_TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA(0x5B),
    UNOFFICIAL_TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA(0x5C),
    TLS_RSA_EXPORT1024_WITH_RC4_56_MD5(0x60),
    TLS_RSA_EXPORT1024_WITH_RC2_56_MD5(0x61),
    TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA(0x62),
    TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA(0x63),
    TLS_RSA_EXPORT1024_WITH_RC4_56_SHA(0x64),
    TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA(0x65),
    TLS_DHE_DSS_WITH_RC4_128_SHA(0x66),
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256(0x67),
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256(0x68),
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256(0x69),
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256(0x6A),
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256(0x6B),
    TLS_DH_anon_WITH_AES_128_CBC_SHA256(0x6C),
    TLS_DH_anon_WITH_AES_256_CBC_SHA256(0x6D),
    TLS_GOSTR341094_WITH_28147_CNT_IMIT(0x80),
    TLS_GOSTR341001_WITH_28147_CNT_IMIT(0x81),
    TLS_GOSTR341094_WITH_NULL_GOSTR3411(0x82),
    TLS_GOSTR341001_WITH_NULL_GOSTR3411(0x83),
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA(0x84),
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA(0x85),
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA(0x86),
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA(0x87),
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA(0x88),
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA(0x89),
    TLS_PSK_WITH_RC4_128_SHA(0x8A),
    TLS_PSK_WITH_3DES_EDE_CBC_SHA(0x8B),
    TLS_PSK_WITH_AES_128_CBC_SHA(0x8C),
    TLS_PSK_WITH_AES_256_CBC_SHA(0x8D),
    TLS_DHE_PSK_WITH_RC4_128_SHA(0x8E),
    TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA(0x8F),
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA(0x90),
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA(0x91),
    TLS_RSA_PSK_WITH_RC4_128_SHA(0x92),
    TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA(0x93),
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA(0x94),
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA(0x95),
    TLS_RSA_WITH_SEED_CBC_SHA(0x96),
    TLS_DH_DSS_WITH_SEED_CBC_SHA(0x97),
    TLS_DH_RSA_WITH_SEED_CBC_SHA(0x98),
    TLS_DHE_DSS_WITH_SEED_CBC_SHA(0x99),
    TLS_DHE_RSA_WITH_SEED_CBC_SHA(0x9A),
    TLS_DH_anon_WITH_SEED_CBC_SHA(0x9B),
    TLS_RSA_WITH_AES_128_GCM_SHA256(0x9C),
    TLS_RSA_WITH_AES_256_GCM_SHA384(0x9D),
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256(0x9E),
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384(0x9F),
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256(0xA0),
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384(0xA1),
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256(0xA2),
    TLS_DHE_DSS_WITH_AES_256_GCM_SHA384(0xA3),
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256(0xA4),
    TLS_DH_DSS_WITH_AES_256_GCM_SHA384(0xA5),
    TLS_DH_anon_WITH_AES_128_GCM_SHA256(0xA6),
    TLS_DH_anon_WITH_AES_256_GCM_SHA384(0xA7),
    TLS_PSK_WITH_AES_128_GCM_SHA256(0xA8),
    TLS_PSK_WITH_AES_256_GCM_SHA384(0xA9),
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256(0xAA),
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384(0xAB),
    TLS_RSA_PSK_WITH_AES_128_GCM_SHA256(0xAC),
    TLS_RSA_PSK_WITH_AES_256_GCM_SHA384(0xAD),
    TLS_PSK_WITH_AES_128_CBC_SHA256(0xAE),
    TLS_PSK_WITH_AES_256_CBC_SHA384(0xAF),
    TLS_PSK_WITH_NULL_SHA256(0xB0),
    TLS_PSK_WITH_NULL_SHA384(0xB1),
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA256(0xB2),
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA384(0xB3),
    TLS_DHE_PSK_WITH_NULL_SHA256(0xB4),
    TLS_DHE_PSK_WITH_NULL_SHA384(0xB5),
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA256(0xB6),
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA384(0xB7),
    TLS_RSA_PSK_WITH_NULL_SHA256(0xB8),
    TLS_RSA_PSK_WITH_NULL_SHA384(0xB9),
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256(0xBA),
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256(0xBB),
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256(0xBC),
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256(0xBD),
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256(0xBE),
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256(0xBF),
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256(0xC0),
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256(0xC1),
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256(0xC2),
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256(0xC3),
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256(0xC4),
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256(0xC5),
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV(0xFF),
    TLS_AES_128_GCM_SHA256(0x1301),
    TLS_AES_256_GCM_SHA384(0x1302),
    TLS_CHACHA20_POLY1305_SHA256(0x1303),
    TLS_AES_128_CCM_SHA256(0x1304),
    TLS_AES_128_CCM_8_SHA256(0x1305),
    TLS_FALLBACK_SCSV(0x5600),
    TLS_ECDH_ECDSA_WITH_NULL_SHA(0xC001),
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA(0xC002),
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA(0xC003),
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA(0xC004),
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA(0xC005),
    TLS_ECDHE_ECDSA_WITH_NULL_SHA(0xC006),
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA(0xC007),
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA(0xC008),
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(0xC009),
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(0xC00A),
    TLS_ECDH_RSA_WITH_NULL_SHA(0xC00B),
    TLS_ECDH_RSA_WITH_RC4_128_SHA(0xC00C),
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA(0xC00D),
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA(0xC00E),
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA(0xC00F),
    TLS_ECDHE_RSA_WITH_NULL_SHA(0xC010),
    TLS_ECDHE_RSA_WITH_RC4_128_SHA(0xC011),
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA(0xC012),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(0xC013),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(0xC014),
    TLS_ECDH_anon_WITH_NULL_SHA(0xC015),
    TLS_ECDH_anon_WITH_RC4_128_SHA(0xC016),
    TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA(0xC017),
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA(0xC018),
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA(0xC019),
    TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA(0xC01A),
    TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA(0xC01B),
    TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA(0xC01C),
    TLS_SRP_SHA_WITH_AES_128_CBC_SHA(0xC01D),
    TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA(0xC01E),
    TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA(0xC01F),
    TLS_SRP_SHA_WITH_AES_256_CBC_SHA(0xC020),
    TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA(0xC021),
    TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA(0xC022),
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256(0xC023),
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384(0xC024),
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256(0xC025),
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384(0xC026),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256(0xC027),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384(0xC028),
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256(0xC029),
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384(0xC02A),
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xC02B),
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384(0xC02C),
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256(0xC02D),
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384(0xC02E),
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(0xC02F),
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(0xC030),
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256(0xC031),
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384(0xC032),
    TLS_ECDHE_PSK_WITH_RC4_128_SHA(0xC033),
    TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA(0xC034),
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA(0xC035),
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA(0xC036),
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256(0xC037),
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384(0xC038),
    TLS_ECDHE_PSK_WITH_NULL_SHA(0xC039),
    TLS_ECDHE_PSK_WITH_NULL_SHA256(0xC03A),
    TLS_ECDHE_PSK_WITH_NULL_SHA384(0xC03B),
    TLS_RSA_WITH_ARIA_128_CBC_SHA256(0xC03C),
    TLS_RSA_WITH_ARIA_256_CBC_SHA384(0xC03D),
    TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256(0xC03E),
    TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384(0xC03F),
    TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256(0xC040),
    TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384(0xC041),
    TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256(0xC042),
    TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384(0xC043),
    TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256(0xC044),
    TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384(0xC045),
    TLS_DH_anon_WITH_ARIA_128_CBC_SHA256(0xC046),
    TLS_DH_anon_WITH_ARIA_256_CBC_SHA384(0xC047),
    TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256(0xC048),
    TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384(0xC049),
    TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256(0xC04A),
    TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384(0xC04B),
    TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256(0xC04C),
    TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384(0xC04D),
    TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256(0xC04E),
    TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384(0xC04F),
    TLS_RSA_WITH_ARIA_128_GCM_SHA256(0xC050),
    TLS_RSA_WITH_ARIA_256_GCM_SHA384(0xC051),
    TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256(0xC052),
    TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384(0xC053),
    TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256(0xC054),
    TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384(0xC055),
    TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256(0xC056),
    TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384(0xC057),
    TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256(0xC058),
    TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384(0xC059),
    TLS_DH_anon_WITH_ARIA_128_GCM_SHA256(0xC05A),
    TLS_DH_anon_WITH_ARIA_256_GCM_SHA384(0xC05B),
    TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256(0xC05C),
    TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384(0xC05D),
    TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256(0xC05E),
    TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384(0xC05F),
    TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256(0xC060),
    TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384(0xC061),
    TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256(0xC062),
    TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384(0xC063),
    TLS_PSK_WITH_ARIA_128_CBC_SHA256(0xC064),
    TLS_PSK_WITH_ARIA_256_CBC_SHA384(0xC065),
    TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256(0xC066),
    TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384(0xC067),
    TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256(0xC068),
    TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384(0xC069),
    TLS_PSK_WITH_ARIA_128_GCM_SHA256(0xC06A),
    TLS_PSK_WITH_ARIA_256_GCM_SHA384(0xC06B),
    TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256(0xC06C),
    TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384(0xC06D),
    TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256(0xC06E),
    TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384(0xC06F),
    TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256(0xC070),
    TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384(0xC071),
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256(0xC072),
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384(0xC073),
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256(0xC074),
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384(0xC075),
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256(0xC076),
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384(0xC077),
    TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256(0xC078),
    TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384(0xC079),
    TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC07A),
    TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC07B),
    TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC07C),
    TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC07D),
    TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC07E),
    TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC07F),
    TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256(0xC080),
    TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384(0xC081),
    TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256(0xC082),
    TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384(0xC083),
    TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256(0xC084),
    TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384(0xC085),
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256(0xC086),
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384(0xC087),
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256(0xC088),
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384(0xC089),
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC08A),
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC08B),
    TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC08C),
    TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC08D),
    TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256(0xC08E),
    TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384(0xC08F),
    TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256(0xC090),
    TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384(0xC091),
    TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256(0xC092),
    TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384(0xC093),
    TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC094),
    TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC095),
    TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC096),
    TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC097),
    TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC098),
    TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC099),
    TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC09A),
    TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC09B),
    TLS_RSA_WITH_AES_128_CCM(0xC09C),
    TLS_RSA_WITH_AES_256_CCM(0xC09D),
    TLS_DHE_RSA_WITH_AES_128_CCM(0xC09E),
    TLS_DHE_RSA_WITH_AES_256_CCM(0xC09F),
    TLS_RSA_WITH_AES_128_CCM_8(0xC0A0),
    TLS_RSA_WITH_AES_256_CCM_8(0xC0A1),
    TLS_DHE_RSA_WITH_AES_128_CCM_8(0xC0A2),
    TLS_DHE_RSA_WITH_AES_256_CCM_8(0xC0A3),
    TLS_PSK_WITH_AES_128_CCM(0xC0A4),
    TLS_PSK_WITH_AES_256_CCM(0xC0A5),
    TLS_DHE_PSK_WITH_AES_128_CCM(0xC0A6),
    TLS_DHE_PSK_WITH_AES_256_CCM(0xC0A7),
    TLS_PSK_WITH_AES_128_CCM_8(0xC0A8),
    TLS_PSK_WITH_AES_256_CCM_8(0xC0A9),
    TLS_PSK_DHE_WITH_AES_128_CCM_8(0xC0AA),
    TLS_PSK_DHE_WITH_AES_256_CCM_8(0xC0AB),
    TLS_PSK_DHE_WITH_AES_256_CCM_80(0xC0AB),
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM(0xC0AC),
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM(0xC0AD),
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8(0xC0AE),
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8(0xC0AF),
    TLS_ECCPWD_WITH_AES_128_GCM_SHA256(0xC0B0),
    TLS_ECCPWD_WITH_AES_256_GCM_SHA384(0xC0B1),
    TLS_ECCPWD_WITH_AES_128_CCM_SHA256(0xC0B2),
    TLS_ECCPWD_WITH_AES_256_CCM_SHA384(0xC0B3),
    // *************************************************************************
    // Unofficial cipher suites draft-mavrogiannopoulos-chacha-tls-01
    // These cipher suite are from a Draft and also don't have a mac algorithm
    // defined
    UNOFFICIAL_TLS_RSA_WITH_CHACHA20_POLY1305(0xCC12),
    UNOFFICIAL_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xcc13),
    UNOFFICIAL_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256(0xcc14),
    UNOFFICIAL_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xcc15),
    UNOFFICIAL_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_OLD(0xCC16),
    UNOFFICIAL_TLS_PSK_WITH_CHACHA20_POLY1305_OLD(0xCC17),
    UNOFFICIAL_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_OLD(0xCC18),
    UNOFFICIAL_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_OLD(0xCC19),
    // *************************************************************************
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xCCA8),
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256(0xCCA9),
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xCCAA),
    TLS_PSK_WITH_CHACHA20_POLY1305_SHA256(0xCCAB),
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256(0xCCAC),
    TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256(0xCCAD),
    TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256(0xCCAE),
    TLS_CECPQ1_RSA_WITH_CHACHA20_POLY1305_SHA256(0x16B7),
    TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256(0x16B8),
    TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384(0x16B9),
    TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384(0x16BA),
    TLS_RSA_WITH_RABBIT_CBC_SHA(0x00FD), // non rfc, only wolfssl
    // GREASE constants
    GREASE_00(0x0A0A),
    GREASE_01(0x1A1A),
    GREASE_02(0x2A2A),
    GREASE_03(0x3A3A),
    GREASE_04(0x4A4A),
    GREASE_05(0x5A5A),
    GREASE_06(0x6A6A),
    GREASE_07(0x7A7A),
    GREASE_08(0x8A8A),
    GREASE_09(0x9A9A),
    GREASE_10(0xAAAA),
    GREASE_11(0xBABA),
    GREASE_12(0xCACA),
    GREASE_13(0xDADA),
    GREASE_14(0xEAEA),
    GREASE_15(0xFAFA),
    TLS_GOSTR341112_256_WITH_28147_CNT_IMIT(0xFF85),
    TLS_GOSTR341112_256_WITH_NULL_GOSTR3411(0xFF87);

    private int value;

    public static final int EXPORT_SYMMETRIC_KEY_SIZE_BYTES = 5;

    private static final Map<Integer, CipherSuite> MAP;

    private CipherSuite(int value) {
        this.value = value;
    }

    public static CipherSuite getRandom(Random random) {
        CipherSuite c = null;
        while (c == null) {
            Object[] o = MAP.values().toArray();
            c = (CipherSuite) o[random.nextInt(o.length)];
        }
        return c;
    }

    static {
        MAP = new HashMap<>();
        for (CipherSuite c : CipherSuite.values()) {
            MAP.put(c.value, c);
        }
    }

    private static int valueToInt(byte[] value) {
        if (value.length >= 2) {
            return (value[0] & 0xff) << Bits.IN_A_BYTE | (value[1] & 0xff);
        } else if (value.length == 1) {
            return value[0];
        } else {
            return 0;
        }
    }

    public static List<CipherSuite> getCipherSuites(byte[] values) {
        List<CipherSuite> cipherSuites = new LinkedList<>();
        int pointer = 0;
        if (values.length % 2 != 0) {
            throw new UnknownCipherSuiteException("Last CipherSuit are unknown!");
        }
        while (pointer < values.length) {
            byte[] suite = new byte[2];
            suite[0] = values[pointer];
            suite[1] = values[pointer + 1];
            cipherSuites.add(getCipherSuite(suite));
            pointer += 2;
        }
        return cipherSuites;
    }

    public boolean isRealCipherSuite() {
        if (isSCSV() || isGrease()) {
            return false;
        } else {
            return true;
        }
    }

    public static CipherSuite getCipherSuite(byte[] value) {
        return getCipherSuite(valueToInt(value));
    }

    public static CipherSuite getCipherSuite(int value) {
        CipherSuite cs = MAP.get(value);
        return cs;
    }

    public byte[] getByteValue() {
        return ArrayConverter.intToBytes(value, 2);
    }

    public int getValue() {
        return value;
    }

    /**
     * Returns true in case the cipher suite enforces ephemeral keys. This is the case for ECDHE and
     * DHE cipher suites.
     *
     * @return True if the cipher suite is Ephemeral
     */
    public boolean isEphemeral() {
        return this.name().contains("DHE_") || this.isAnon() || this.isPWD() || this.isTLS13();
    }

    public boolean isPskOrDhPsk() {
        if (!this.name().contains("RSA")) {
            return this.name().contains("PSK");
        } else {
            return false;
        }
    }

    public boolean isPsk() {
        return this.name().contains("PSK");
    }

    public boolean isSrpSha() {
        return this.name().contains("SRP_SHA");
    }

    public boolean isSrp() {
        return this.name().contains("SRP_");
    }

    public boolean isExport() {
        return this.name().contains("EXPORT");
    }

    public boolean isGrease() {
        return this.name().contains("GREASE");
    }

    public boolean isExportSymmetricCipher() {
        return this.name().contains("DES40")
                || this.name().contains("RC4_40")
                || this.name().contains("RC2_CBC_40")
                || this.name().contains("DES_CBC_40");
    }

    /**
     * Returns true in case the cipher suite is a CBC cipher suite.
     *
     * @return True if the cipher suite is cbc
     */
    public boolean isCBC() {
        return (this.name().contains("_CBC"));
    }

    public Boolean isUsingPadding(ProtocolVersion protocolVersion) {
        CipherType type = AlgorithmResolver.getCipherType(this);
        switch (type) {
            case STREAM:
                return false;
            case BLOCK:
                return true;
            case AEAD:
                if (protocolVersion != ProtocolVersion.TLS13) {
                    return false;
                } else {
                    return true;
                }
        }
        return null;
    }

    public boolean isUsingMac() {
        if (this.name().contains("NULL")) {
            String cipher = this.toString();
            if (cipher.endsWith("NULL")) {
                return false;
            }
            String[] hashFunctionNames = {
                "MD5", "SHA", "SHA256", "SHA384", "SHA512", "IMIT", "GOSTR3411"
            };
            for (String hashFunction : hashFunctionNames) {
                if (cipher.endsWith(hashFunction)) {
                    return true;
                }
            }
            return false;
        }
        return (this.name().contains("_CBC")
                || this.name().contains("RC4")
                || this.name().contains("CNT"));
    }

    public boolean isSCSV() {
        return (this.name().contains("SCSV"));
    }

    public boolean isGCM() {
        return (this.name().contains("_GCM"));
    }

    public boolean isCCM() {
        return (this.name().contains("_CCM"));
    }

    public boolean isCCM_8() {
        return (this.name().contains("_CCM_8"));
    }

    public boolean isOCB() {
        return (this.name().contains("_OCB"));
    }

    public boolean isSteamCipherWithIV() {
        return this.name().contains("28147_CNT");
    }

    public boolean isAEAD() {
        return this.isCCM() || this.isChachaPoly() || this.isGCM() || this.isOCB();
    }

    public boolean usesSHA384() {
        return this.name().endsWith("SHA384");
    }

    public boolean usesGOSTR3411() {
        return this.name().startsWith("TLS_GOSTR3410");
    }

    public boolean usesGOSTR34112012() {
        return this.name().startsWith("TLS_GOSTR3411");
    }

    public boolean usesStrictExplicitIv() {
        return (this.name().contains("CHACHA20_POLY1305"));
    }

    public boolean usesDH() {
        return (this.name().contains("_DH"));
    }

    /**
     * Returns true if the cipher suite is supported by the specified protocol version. TODO: this
     * is still very imprecise and must be improved with new ciphers.
     *
     * @param version The ProtocolVersion to check
     * @return True if the cipher suite is supported in the ProtocolVersion
     */
    public boolean isSupportedInProtocol(ProtocolVersion version) {
        if (version == ProtocolVersion.SSL3) {
            return SSL3_SUPPORTED_CIPHERSUITES.contains(this);
        }

        if (this.isTLS13()) {
            return version == ProtocolVersion.TLS13;
        }

        if (this.isGCM()) {
            return version == ProtocolVersion.TLS12
                    || version == ProtocolVersion.DTLS12
                    || version == ProtocolVersion.TLS13;
        }

        if (this.name().endsWith("256")
                || this.name().endsWith("384")
                || this.isCCM()
                || this.isCCM_8()) {
            return ((version == ProtocolVersion.TLS12) || (version == ProtocolVersion.DTLS12));
        }
        if (this.name().contains("IDEA")
                || this.name().contains("_DES")
                || this.isExportSymmetricCipher()) {
            return !((version == ProtocolVersion.TLS12) || (version == ProtocolVersion.DTLS12));
        }

        return true;
    }

    @SuppressWarnings("SpellCheckingInspection")
    public static final Set<CipherSuite> SSL3_SUPPORTED_CIPHERSUITES =
            Collections.unmodifiableSet(
                    new HashSet<>(
                            Arrays.asList(
                                    TLS_NULL_WITH_NULL_NULL,
                                    TLS_RSA_WITH_NULL_MD5,
                                    TLS_RSA_WITH_NULL_SHA,
                                    TLS_RSA_EXPORT_WITH_RC4_40_MD5,
                                    TLS_RSA_WITH_RC4_128_MD5,
                                    TLS_RSA_WITH_RC4_128_SHA,
                                    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
                                    TLS_RSA_WITH_IDEA_CBC_SHA,
                                    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
                                    TLS_RSA_WITH_DES_CBC_SHA,
                                    TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                                    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
                                    TLS_DH_DSS_WITH_DES_CBC_SHA,
                                    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
                                    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
                                    TLS_DH_RSA_WITH_DES_CBC_SHA,
                                    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
                                    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
                                    TLS_DHE_DSS_WITH_DES_CBC_SHA,
                                    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
                                    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
                                    TLS_DHE_RSA_WITH_DES_CBC_SHA,
                                    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                                    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                                    TLS_DH_anon_WITH_RC4_128_MD5,
                                    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
                                    TLS_DH_anon_WITH_DES_CBC_SHA,
                                    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
                                    TLS_ECCPWD_WITH_AES_128_CCM_SHA256,
                                    TLS_ECCPWD_WITH_AES_128_GCM_SHA256,
                                    TLS_ECCPWD_WITH_AES_256_CCM_SHA384,
                                    TLS_ECCPWD_WITH_AES_256_GCM_SHA384)));

    public static List<CipherSuite> getImplemented() {
        List<CipherSuite> list = new LinkedList<>();
        list.add(TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_RSA_WITH_AES_128_CBC_SHA);
        list.add(TLS_RSA_WITH_NULL_MD5);
        list.add(TLS_RSA_WITH_NULL_SHA);
        list.add(TLS_RSA_WITH_AES_128_CBC_SHA256);
        list.add(TLS_RSA_WITH_AES_256_CBC_SHA256);
        list.add(TLS_RSA_WITH_AES_256_CBC_SHA);
        list.add(TLS_RSA_WITH_CAMELLIA_128_CBC_SHA);
        list.add(TLS_RSA_WITH_CAMELLIA_256_CBC_SHA);
        list.add(TLS_RSA_WITH_IDEA_CBC_SHA);
        list.add(TLS_RSA_WITH_DES_CBC_SHA);
        list.add(TLS_RSA_WITH_SEED_CBC_SHA);
        list.add(TLS_RSA_WITH_RC4_128_MD5);
        list.add(TLS_RSA_WITH_RC4_128_SHA);
        list.add(TLS_RSA_WITH_AES_128_CCM);
        list.add(TLS_RSA_WITH_AES_256_CCM);
        list.add(TLS_RSA_WITH_AES_128_GCM_SHA256);
        list.add(TLS_RSA_WITH_AES_256_GCM_SHA384);
        list.add(TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_DH_anon_EXPORT_WITH_RC4_40_MD5);
        list.add(TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA);
        list.add(TLS_DH_anon_WITH_RC4_128_MD5);
        list.add(TLS_DH_anon_WITH_DES_CBC_SHA);
        list.add(TLS_DH_anon_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_DH_DSS_WITH_AES_128_CBC_SHA);
        list.add(TLS_DH_RSA_WITH_AES_128_CBC_SHA);
        list.add(TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        list.add(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        list.add(TLS_DH_anon_WITH_AES_128_CBC_SHA);
        list.add(TLS_DH_DSS_WITH_AES_256_CBC_SHA);
        list.add(TLS_DH_RSA_WITH_AES_256_CBC_SHA);
        list.add(TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
        list.add(TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
        list.add(TLS_DH_anon_WITH_AES_256_CBC_SHA);
        list.add(TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
        list.add(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA);
        list.add(TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);
        list.add(TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
        list.add(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA);
        list.add(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        list.add(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
        list.add(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384);
        list.add(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384);
        list.add(TLS_DH_RSA_WITH_AES_256_GCM_SHA384);
        list.add(TLS_DH_RSA_WITH_AES_128_GCM_SHA256);
        list.add(TLS_DH_DSS_WITH_AES_256_GCM_SHA384);
        list.add(TLS_DH_anon_WITH_AES_128_GCM_SHA256);
        list.add(TLS_DH_anon_WITH_AES_256_GCM_SHA384);
        list.add(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
        list.add(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
        list.add(TLS_DHE_RSA_WITH_AES_128_CBC_SHA256);
        list.add(TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);
        list.add(TLS_DH_anon_WITH_AES_128_CBC_SHA256);
        list.add(TLS_DH_anon_WITH_AES_256_CBC_SHA256);
        list.add(TLS_DHE_RSA_WITH_DES_CBC_SHA);
        list.add(TLS_DHE_RSA_WITH_AES_128_CCM);
        list.add(TLS_DHE_RSA_WITH_AES_256_CCM);
        list.add(TLS_DHE_RSA_WITH_SEED_CBC_SHA);
        list.add(TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA);
        list.add(TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA);
        list.add(TLS_DHE_DSS_WITH_AES_128_GCM_SHA256);
        list.add(TLS_DHE_DSS_WITH_AES_256_GCM_SHA384);
        list.add(TLS_DHE_DSS_WITH_RC4_128_SHA);
        list.add(TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256);
        list.add(TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384);
        list.add(TLS_ECDHE_RSA_WITH_RC4_128_SHA);
        list.add(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        list.add(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        list.add(TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256);
        list.add(TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_128_CCM);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_256_CCM);
        list.add(TLS_AES_128_GCM_SHA256);
        list.add(TLS_AES_256_GCM_SHA384);
        list.add(TLS_CHACHA20_POLY1305_SHA256);
        list.add(TLS_AES_128_CCM_SHA256);
        list.add(TLS_AES_128_CCM_8_SHA256);
        list.add(TLS_PSK_WITH_AES_128_CBC_SHA);
        list.add(TLS_PSK_DHE_WITH_AES_128_CCM_8);
        list.add(TLS_PSK_DHE_WITH_AES_256_CCM_8);
        list.add(TLS_PSK_DHE_WITH_AES_256_CCM_80);
        list.add(TLS_PSK_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_PSK_WITH_AES_128_CBC_SHA256);
        list.add(TLS_PSK_WITH_AES_128_CCM);
        list.add(TLS_PSK_WITH_AES_128_CCM_8);
        list.add(TLS_PSK_WITH_AES_128_GCM_SHA256);
        list.add(TLS_PSK_WITH_AES_256_CBC_SHA);
        list.add(TLS_PSK_WITH_AES_256_CBC_SHA384);
        list.add(TLS_PSK_WITH_AES_256_CCM);
        list.add(TLS_PSK_WITH_AES_256_CCM_8);
        list.add(TLS_PSK_WITH_AES_256_GCM_SHA384);
        list.add(TLS_PSK_WITH_RC4_128_SHA);
        list.add(TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_DHE_PSK_WITH_AES_128_CBC_SHA);
        list.add(TLS_DHE_PSK_WITH_AES_128_CCM);
        list.add(TLS_DHE_PSK_WITH_AES_128_GCM_SHA256);
        list.add(TLS_DHE_PSK_WITH_AES_256_CBC_SHA);
        list.add(TLS_DHE_PSK_WITH_AES_256_CBC_SHA384);
        list.add(TLS_DHE_PSK_WITH_AES_256_CCM);
        list.add(TLS_DHE_PSK_WITH_AES_256_GCM_SHA384);
        list.add(TLS_DHE_PSK_WITH_RC4_128_SHA);
        list.add(TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
        list.add(TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA);
        list.add(TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384);
        list.add(TLS_ECDHE_PSK_WITH_RC4_128_SHA);
        list.add(TLS_DH_RSA_WITH_DES_CBC_SHA);
        list.add(TLS_DH_RSA_WITH_AES_128_CBC_SHA256);
        list.add(TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA);
        list.add(UNOFFICIAL_TLS_ECDH_ECDSA_WITH_RC4_128_SHA);
        list.add(UNOFFICIAL_TLS_ECDH_ECDSA_WITH_DES_CBC_SHA);
        list.add(UNOFFICIAL_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
        list.add(TLS_DH_DSS_WITH_AES_256_CBC_SHA256);
        list.add(TLS_DH_RSA_WITH_AES_256_CBC_SHA256);
        list.add(TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA);
        list.add(TLS_RSA_PSK_WITH_RC4_128_SHA);
        list.add(TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_RSA_PSK_WITH_AES_128_CBC_SHA);
        list.add(TLS_RSA_PSK_WITH_AES_256_CBC_SHA);
        list.add(TLS_DH_RSA_WITH_SEED_CBC_SHA);
        list.add(TLS_RSA_PSK_WITH_AES_128_GCM_SHA256);
        list.add(TLS_RSA_PSK_WITH_AES_256_GCM_SHA384);
        list.add(TLS_DHE_PSK_WITH_AES_128_CBC_SHA256);
        list.add(TLS_RSA_PSK_WITH_AES_128_CBC_SHA256);
        list.add(TLS_RSA_PSK_WITH_AES_256_CBC_SHA384);
        list.add(TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256);
        list.add(TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256);
        list.add(TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256);
        list.add(TLS_ECDH_ECDSA_WITH_RC4_128_SHA);
        list.add(TLS_ECDHE_ECDSA_WITH_RC4_128_SHA);
        list.add(TLS_ECDH_RSA_WITH_RC4_128_SHA);
        list.add(TLS_ECDH_anon_WITH_NULL_SHA);
        list.add(TLS_SRP_SHA_WITH_AES_128_CBC_SHA);
        list.add(TLS_SRP_SHA_WITH_AES_256_CBC_SHA);
        list.add(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256);
        list.add(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384);
        list.add(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256);
        list.add(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384);
        list.add(TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256);
        list.add(TLS_RSA_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_RSA_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_RSA_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_RSA_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_PSK_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_PSK_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_PSK_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_PSK_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384);
        list.add(TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384);
        list.add(TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384);
        list.add(TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384);
        list.add(TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384);
        list.add(TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384);
        list.add(TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384);
        list.add(TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384);
        list.add(TLS_PSK_WITH_NULL_SHA);
        list.add(TLS_DHE_PSK_WITH_NULL_SHA);
        list.add(TLS_RSA_PSK_WITH_NULL_SHA);
        list.add(TLS_RSA_WITH_NULL_SHA256);
        list.add(UNOFFICIAL_TLS_ECDH_ECDSA_WITH_NULL_SHA);
        list.add(TLS_PSK_WITH_NULL_SHA256);
        list.add(TLS_PSK_WITH_NULL_SHA384);
        list.add(TLS_DHE_PSK_WITH_NULL_SHA256);
        list.add(TLS_DHE_PSK_WITH_NULL_SHA384);
        list.add(TLS_RSA_PSK_WITH_NULL_SHA256);
        list.add(TLS_RSA_PSK_WITH_NULL_SHA384);
        list.add(TLS_ECDH_ECDSA_WITH_NULL_SHA);
        list.add(TLS_ECDHE_ECDSA_WITH_NULL_SHA);
        list.add(TLS_ECDH_RSA_WITH_NULL_SHA);
        list.add(TLS_ECDHE_RSA_WITH_NULL_SHA);
        list.add(TLS_ECDHE_PSK_WITH_NULL_SHA);
        list.add(TLS_ECDHE_PSK_WITH_NULL_SHA256);
        list.add(TLS_ECDHE_PSK_WITH_NULL_SHA384);
        list.add(TLS_DH_DSS_WITH_DES_CBC_SHA);
        list.add(TLS_DHE_DSS_WITH_DES_CBC_SHA);
        list.add(TLS_DH_DSS_WITH_AES_128_CBC_SHA256);
        list.add(TLS_DHE_DSS_WITH_AES_128_CBC_SHA256);
        list.add(TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA);
        list.add(TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA);
        list.add(TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA);
        list.add(UNOFFICIAL_TLS_ECDH_anon_WITH_NULL_SHA);
        list.add(UNOFFICIAL_TLS_ECDH_anon_WITH_RC4_128_SHA);
        list.add(UNOFFICIAL_TLS_ECDH_anon_WITH_DES_CBC_SHA);
        list.add(UNOFFICIAL_TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_DHE_DSS_WITH_AES_256_CBC_SHA256);
        list.add(TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA);
        list.add(TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA);
        list.add(TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA);
        list.add(TLS_DH_DSS_WITH_SEED_CBC_SHA);
        list.add(TLS_DHE_DSS_WITH_SEED_CBC_SHA);
        list.add(TLS_DH_anon_WITH_SEED_CBC_SHA);
        list.add(TLS_DH_DSS_WITH_AES_128_GCM_SHA256);
        list.add(TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256);
        list.add(TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256);
        list.add(TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256);
        list.add(TLS_ECDH_anon_WITH_RC4_128_SHA);
        list.add(TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_ECDH_anon_WITH_AES_128_CBC_SHA);
        list.add(TLS_ECDH_anon_WITH_AES_256_CBC_SHA);
        list.add(TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_DH_anon_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_DH_anon_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_DH_anon_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_DH_anon_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_GOSTR341001_WITH_28147_CNT_IMIT);
        list.add(TLS_GOSTR341001_WITH_NULL_GOSTR3411);
        list.add(TLS_GOSTR341112_256_WITH_28147_CNT_IMIT);
        list.add(TLS_GOSTR341112_256_WITH_NULL_GOSTR3411);
        list.add(TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        list.add(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
        list.add(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        list.add(TLS_ECCPWD_WITH_AES_128_GCM_SHA256);
        list.add(TLS_ECCPWD_WITH_AES_256_GCM_SHA384);
        list.add(TLS_ECCPWD_WITH_AES_128_CCM_SHA256);
        list.add(TLS_ECCPWD_WITH_AES_256_CCM_SHA384);
        list.add(TLS_RSA_WITH_AES_128_CCM_8);
        list.add(TLS_RSA_WITH_AES_256_CCM_8);
        list.add(TLS_DHE_RSA_WITH_AES_128_CCM_8);
        list.add(TLS_DHE_RSA_WITH_AES_256_CCM_8);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8);
        list.add(TLS_PSK_WITH_CHACHA20_POLY1305_SHA256);
        list.add(TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256);
        list.add(TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256);
        list.add(TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256);
        list.add(UNOFFICIAL_TLS_RSA_WITH_CHACHA20_POLY1305);
        list.add(UNOFFICIAL_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        list.add(UNOFFICIAL_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
        list.add(UNOFFICIAL_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        list.add(UNOFFICIAL_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_OLD);
        list.add(UNOFFICIAL_TLS_PSK_WITH_CHACHA20_POLY1305_OLD);
        list.add(UNOFFICIAL_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_OLD);
        list.add(UNOFFICIAL_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_OLD);
        list.add(TLS_RSA_EXPORT_WITH_RC4_40_MD5);
        list.add(TLS_RSA_EXPORT_WITH_DES40_CBC_SHA);
        list.add(TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5);
        list.add(TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA);
        list.add(TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA);
        list.add(TLS_NULL_WITH_NULL_NULL);
        return list;
    }

    public static List<CipherSuite> getEsniImplemented() {
        List<CipherSuite> list = new LinkedList();
        list.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        list.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        list.add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
        list.add(CipherSuite.TLS_AES_128_CCM_SHA256);
        list.add(CipherSuite.TLS_AES_128_CCM_8_SHA256);
        return list;
    }

    public static List<CipherSuite> getTls13CipherSuites() {
        List<CipherSuite> list = new LinkedList();
        list.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        list.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        list.add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
        list.add(CipherSuite.TLS_AES_128_CCM_SHA256);
        list.add(CipherSuite.TLS_AES_128_CCM_8_SHA256);
        return list;
    }

    public static List<CipherSuite> getImplementedTls13CipherSuites() {
        List<CipherSuite> list = new LinkedList();
        list.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        list.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        list.add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
        list.add(CipherSuite.TLS_AES_128_CCM_SHA256);
        list.add(CipherSuite.TLS_AES_128_CCM_8_SHA256);
        return list;
    }

    public static List<CipherSuite> getNotImplemented() {
        List<CipherSuite> notImplemented = new LinkedList<>();
        for (CipherSuite suite : values()) {
            if (!getImplemented().contains(suite)) {
                notImplemented.add(suite);
            }
        }
        return notImplemented;
    }

    /**
     * Returns true if the cipher suite a TLS 1.3 cipher suite
     *
     * @return True if the Ciphersuite is supported in TLS 1.3
     */
    public boolean isTLS13() {
        return this.getByteValue()[0] == (byte) 0x13 && this.getByteValue()[1] != (byte) 0x00;
    }

    public boolean isImplemented() {
        return getImplemented().contains(this);
    }

    public boolean isSHA() {
        return this.name().endsWith("SHA");
    }

    public boolean isSHA256() {
        return this.name().contains("SHA256");
    }

    public boolean isChachaPoly() {
        return this.name().contains("CHACHA");
    }

    public boolean isSHA384() {
        return this.name().contains("SHA384");
    }

    public boolean isSHA512() {
        return this.name().contains("SHA512");
    }

    public boolean isECDSA() {
        return this.name().contains("ECDSA");
    }

    public boolean isAnon() {
        return this.name().contains("anon");
    }

    public boolean isNull() {
        return this.name().toLowerCase().contains("null");
    }

    public boolean isPWD() {
        return this.name().contains("PWD");
    }

    public boolean isDSS() {
        return this.name().contains("DSS");
    }

    public boolean isGOST() {
        return this.name().contains("GOST");
    }

    // Note: We don't consider DES as weak for these purposes.
    public boolean isWeak() {
        return this.isExport() || this.isExportSymmetricCipher() || this.isAnon() || this.isNull();
    }

    public boolean requiresServerCertificateMessage() {
        return !this.isSrpSha() && !this.isPskOrDhPsk() && !this.isAnon() && !this.isPWD();
    }
}

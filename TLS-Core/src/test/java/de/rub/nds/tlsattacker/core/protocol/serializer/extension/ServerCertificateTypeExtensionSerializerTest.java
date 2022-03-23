/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ServerCertificateTypeExtensionParserTest;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Collection;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ServerCertificateTypeExtensionSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ServerCertificateTypeExtensionParserTest.generateData();
    }

    private final byte[] expectedBytes;
    private final Integer certificateTypesLength;
    private final List<CertificateType> certificateTypes;
    private final ConnectionEndType connectionEndType;
    private ServerCertificateTypeExtensionSerializer serializer;
    private ServerCertificateTypeExtensionMessage msg;

    public ServerCertificateTypeExtensionSerializerTest(byte[] expectedBytes, Integer certificateTypesLength,
        List<CertificateType> certificateTypes, ConnectionEndType connectionEndType) {
        this.expectedBytes = expectedBytes;
        this.certificateTypesLength = certificateTypesLength;
        this.certificateTypes = certificateTypes;
        this.connectionEndType = connectionEndType;
    }

    @Before
    public void setUp() {
        msg = new ServerCertificateTypeExtensionMessage();
        serializer = new ServerCertificateTypeExtensionSerializer(msg);
    }

    @Test
    public void testSerializeExtensionContent() {
        msg.setCertificateTypes(CertificateType.toByteArray(certificateTypes));
        if (certificateTypesLength != null) {
            msg.setCertificateTypesLength(certificateTypesLength);
        } else {
            assertNull(certificateTypesLength);
        }
        msg.setIsClientMessage(connectionEndType == ConnectionEndType.CLIENT);

        assertArrayEquals(expectedBytes, serializer.serializeExtensionContent());
    }
}

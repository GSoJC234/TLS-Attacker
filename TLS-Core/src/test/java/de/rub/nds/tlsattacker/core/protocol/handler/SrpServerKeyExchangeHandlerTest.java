/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.SrpServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.SrpServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.SrpServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.SrpServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class SrpServerKeyExchangeHandlerTest {

    private SrpServerKeyExchangeHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new SrpServerKeyExchangeHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class SrpServerKeyExchangeHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof SrpServerKeyExchangeParser);
    }

    /**
     * Test of getPreparator method, of class SrpServerKeyExchangeHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new SrpServerKeyExchangeMessage()) instanceof SrpServerKeyExchangePreparator);
    }

    /**
     * Test of getSerializer method, of class SrpServerKeyExchangeHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new SrpServerKeyExchangeMessage()) instanceof SrpServerKeyExchangeSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class SrpServerKeyExchangeHandler.
     */

    @Test
    public void testAdjustTLSContext() {
        SrpServerKeyExchangeMessage message = new SrpServerKeyExchangeMessage();
        message.setModulus(BigInteger.TEN.toByteArray());
        message.setGenerator(BigInteger.ONE.toByteArray());
        message.setSalt(BigInteger.TEN.toByteArray());
        message.setPublicKey(new byte[] { 0, 1, 2, 3 });
        context.setSelectedCipherSuite(CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA);
        message.prepareComputations();
        message.getComputations().setPrivateKey(BigInteger.ZERO);
        handler.adjustTLSContext(message);
        assertNull(context.getPreMasterSecret());
    }

    @Test
    public void testAdjustTLSContextWithoutComputations() {
        SrpServerKeyExchangeMessage message = new SrpServerKeyExchangeMessage();
        message.setModulus(BigInteger.TEN.toByteArray());
        message.setGenerator(BigInteger.ONE.toByteArray());
        message.setSalt(BigInteger.TEN.toByteArray());
        message.setPublicKey(new byte[] { 0, 1, 2, 3 });
        handler.adjustTLSContext(message);
        assertNull(context.getPreMasterSecret());
        assertNull(context.getMasterSecret());
    }

}
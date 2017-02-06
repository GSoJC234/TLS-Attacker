/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config.delegate;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class FuzzingModeDelegateTest {

    private FuzzingModeDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    public FuzzingModeDelegateTest() {
    }

    @Before
    public void setUp() {
        this.delegate = new FuzzingModeDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of isFuzzingMode method, of class FuzzingModeDelegate.
     */
    @Test
    public void testIsFuzzingMode() {
        args = new String[1];
        args[0] = "-fuzzing";
        assertFalse(delegate.isFuzzingMode());
        jcommander.parse(args);
        assertTrue(delegate.isFuzzingMode());
    }

    /**
     * Test of setFuzzingMode method, of class FuzzingModeDelegate.
     */
    @Test
    public void testSetFuzzingMode() {
        assertFalse(delegate.isFuzzingMode());
        delegate.setFuzzingMode(true);
        assertTrue(delegate.isFuzzingMode());
    }

    /**
     * Test of applyDelegate method, of class FuzzingModeDelegate.
     */
    @Test
    public void testApplyDelegate() {
        TlsConfig config = new TlsConfig();
        config.setFuzzingMode(false);
        args = new String[1];
        args[0] = "-fuzzing";
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(config.isFuzzingMode());
    }

}

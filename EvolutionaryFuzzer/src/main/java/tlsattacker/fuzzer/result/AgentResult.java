/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.result;

import tlsattacker.fuzzer.instrumentation.InstrumentationMap;
import tlsattacker.fuzzer.server.TLSServer;
import tlsattacker.fuzzer.testvector.TestVector;

/**
 * This class summarizes a the Results of FuzzingVector. It contains information
 * about a potential timeout, or crash. It containts information about the Time
 * the Vector took to Execute, the Controlflow Branches that were executed by
 * the Vector.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AgentResult {

    /**
     * If the Implementation has Crashed
     */
    private final boolean hasCrashed;

    /**
     * If the Implementation did Timeout
     */
    private boolean didTimeout;

    /**
     * The Unixtime @ which the Vector started executing
     */
    private final long startTime;

    /**
     * The Unixtime @ which the Vector finished executing
     */
    private final long stopTime;

    /**
     * The instrumentation result
     */
    private final InstrumentationMap instrumentationMap;

    /**
     * The TestVector that was executed
     */
    private final TestVector vector;

    /**
     * Each AgentResult get an id for easier referencing
     */
    private final String id;

    /**
     * If the AgentResult is considered a good Trace, eg. if it found new
     * Codepaths false means no true means yes and null means, we dont know yet
     */
    private Boolean goodTrace = null;

    /**
     * The Server on which the TestVector was executed on
     */
    private final TLSServer server;

    /**
     * 
     * @param hasCrashed
     * @param didTimeout
     * @param startTime
     * @param stopTime
     * @param instrumentationMap
     * @param vector
     * @param id
     * @param server
     */
    public AgentResult(boolean hasCrashed, boolean didTimeout, long startTime, long stopTime,
            InstrumentationMap instrumentationMap, TestVector vector, String id, TLSServer server) {
        this.hasCrashed = hasCrashed;
        this.didTimeout = didTimeout;
        this.startTime = startTime;
        this.stopTime = stopTime;
        this.instrumentationMap = instrumentationMap;
        this.vector = vector;
        this.id = id;
        this.server = server;
    }

    public Boolean isGoodTrace() {
        return goodTrace;
    }

    public void setGoodTrace(Boolean wasGoodTrace) {
        this.goodTrace = wasGoodTrace;
    }

    public void setDidTimeout(boolean didTimeout) {
        this.didTimeout = didTimeout;
    }

    public String getId() {
        return id;
    }

    public boolean hasCrashed() {
        return hasCrashed;
    }

    public boolean didTimeout() {
        return didTimeout;
    }

    public long getStartTime() {
        return startTime;
    }

    public long getStopTime() {
        return stopTime;
    }

    public InstrumentationMap getInstrumentationMap() {
        return instrumentationMap;
    }

    public TLSServer getServer() {
        return server;
    }

    @Override
    public String toString() {
        return "Result{" + "hasCrashed=" + hasCrashed + ", didTimeout=" + didTimeout + ", startTime=" + startTime
                + ", stopTime=" + stopTime + ", instrumentationMap=" + instrumentationMap.toString() + '}';
    }

    public TestVector getVector() {
        return vector;
    }

}

/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import tlsattacker.fuzzer.config.analyzer.EarlyHeartbeatRuleConfig;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.result.Result;
import tlsattacker.fuzzer.testvector.TestVectorSerializer;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBException;

/**
 * A rule that tries to find TestVectors which allowed Heartbeat messages before
 * the handshake has finished
 * 
 * @author ic0ns
 */
public class EarlyHeartbeatRule extends Rule {

    /**
     *
     */
    private static final Logger LOG = Logger.getLogger(EarlyHeartbeatRule.class.getName());

    /**
     *
     */
    private EarlyHeartbeatRuleConfig config;

    /**
     *
     */
    private int found = 0;

    /**
     * 
     * @param evoConfig
     */
    public EarlyHeartbeatRule(EvolutionaryFuzzerConfig evoConfig) {
	super(evoConfig, "early_heartbeat.rule");
	File f = new File(evoConfig.getAnalyzerConfigFolder() + configFileName);
	if (f.exists()) {
	    config = JAXB.unmarshal(f, EarlyHeartbeatRuleConfig.class);
	}
	if (config == null) {
	    config = new EarlyHeartbeatRuleConfig();
	    writeConfig(config);
	}
	prepareConfigOutputFolder();
    }

    /**
     * 
     * @param result
     * @return
     */
    @Override
    public boolean applies(Result result) {
	WorkflowTrace trace = result.getVector().getTrace();
	if (!trace.getActualReceivedProtocolMessagesOfType(ProtocolMessageType.HEARTBEAT).isEmpty()) {
	    return hasHeartbeatWithoutFinished(trace) || hasHeartbeatBeforeFinished(trace);
	} else {
	    return false;
	}
    }

    /**
     * 
     * @param result
     */
    @Override
    public void onApply(Result result) {
	found++;
	File f = new File(evoConfig.getOutputFolder() + config.getOutputFolder() + result.getId());
	try {
	    result.getVector()
		    .getTrace()
		    .setDescription(
			    "WorkflowTrace has a Heartbeat from the Server before the Server send his finished message!");
	    f.createNewFile();
	    TestVectorSerializer.write(f, result.getVector());
	} catch (JAXBException | IOException E) {
	    LOG.log(Level.SEVERE,
		    "Could not write Results to Disk! Does the Fuzzer have the rights to write to "
			    + f.getAbsolutePath(), E);
	}
    }

    /**
     * 
     * @param result
     */
    @Override
    public void onDecline(Result result) {
    }

    /**
     * 
     * @return
     */
    @Override
    public String report() {
	if (found > 0) {
	    return "Found " + found + " Traces with EarlyHeartBeat messages from the Server\n";
	} else {
	    return null;
	}
    }

    /**
     * 
     * @return
     */
    @Override
    public EarlyHeartbeatRuleConfig getConfig() {
	return config;
    }

    /**
     * 
     * @param trace
     * @return
     */
    public boolean hasHeartbeatWithoutFinished(WorkflowTrace trace) {
	List<HandshakeMessage> finishedMessages = trace
		.getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.FINISHED);
	List<ProtocolMessage> heartBeatMessages = trace
		.getActualReceivedProtocolMessagesOfType(ProtocolMessageType.HEARTBEAT);
	return (finishedMessages.isEmpty() && !heartBeatMessages.isEmpty());
    }

    /**
     * 
     * @param trace
     * @return
     */
    public boolean hasHeartbeatBeforeFinished(WorkflowTrace trace) {
	return trace.actuallyReceivedTypeBeforeType(ProtocolMessageType.HEARTBEAT, HandshakeMessageType.FINISHED);
    }

}

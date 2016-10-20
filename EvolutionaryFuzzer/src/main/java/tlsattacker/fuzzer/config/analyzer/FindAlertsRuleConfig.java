/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config.analyzer;

import de.rub.nds.tlsattacker.tls.constants.AlertDescription;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * A configuration class for the FindAlertsRule
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlRootElement
public class FindAlertsRuleConfig extends RuleConfig {
    // List of Alert codes, if we see this alert we save the workflow trace

    /**
     *
     */
    private Set<Byte> blacklist;
    // Set of RFC Comform Alert Codes, every Code that is not in this list is
    // saved

    /**
     *
     */
    private Set<Byte> whitelist;
    // The Pokemon method, the Rule is advised to save one example testvector
    // for each alert message

    /**
     *
     */
    private boolean saveOneOfEach = true;

    // Output folder relative to the evolutionaryConfig output folder

    /**
     *
     */

    public FindAlertsRuleConfig() {
	super("alerts/");
	this.blacklist = new HashSet<>();
	blacklist.add((byte) 80);
	blacklist.add((byte) 21);
	blacklist.add((byte) 41);
	blacklist.add((byte) 60);

	this.whitelist = new HashSet<>();
	// we add all AlertDescriptions TLS Attacker knows to the whitelist
	for (AlertDescription description : AlertDescription.values()) {
	    whitelist.add(description.getValue());
	}
    }

    /**
     * 
     * @return
     */
    public Set<Byte> getBlacklist() {
	return Collections.unmodifiableSet(blacklist);
    }

    /**
     * 
     * @param blackList
     */
    public void setBlacklist(Set<Byte> blackList) {
	this.blacklist = blackList;
    }

    /**
     * 
     * @return
     */
    public Set<Byte> getWhitelist() {
	return Collections.unmodifiableSet(whitelist);
    }

    /**
     * 
     * @param whitelist
     */
    public void setWhitelist(Set<Byte> whitelist) {
	this.whitelist = whitelist;
    }

    /**
     * 
     * @return
     */
    public boolean isSaveOneOfEach() {
	return saveOneOfEach;
    }

    /**
     * 
     * @param saveOneOfEach
     */
    public void setSaveOneOfEach(boolean saveOneOfEach) {
	this.saveOneOfEach = saveOneOfEach;
    }

    private static final Logger LOG = Logger.getLogger(FindAlertsRuleConfig.class.getName());
}

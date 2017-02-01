/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.extension;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlRootElement;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
@XmlRootElement
public abstract class ExtensionMessage extends ModifiableVariableHolder implements Serializable {

    ExtensionType extensionTypeConstant;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray extensionType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger extensionLength;

    @ModifiableVariableProperty
    ModifiableByteArray extensionBytes;

    public ExtensionMessage() {

    }

    public ModifiableByteArray getExtensionType() {
        return extensionType;
    }

    public ModifiableInteger getExtensionLength() {
        return extensionLength;
    }

    public ModifiableByteArray getExtensionBytes() {
        return extensionBytes;
    }

    public void setExtensionType(byte[] array) {
        this.extensionType = ModifiableVariableFactory.safelySetValue(extensionType, array);
    }

    public void setExtensionLength(int length) {
        this.extensionLength = ModifiableVariableFactory.safelySetValue(extensionLength, length);
    }

    public void setExtensionBytes(byte[] data) {
        this.extensionBytes = ModifiableVariableFactory.safelySetValue(extensionBytes, data);
    }

    public void setExtensionType(ModifiableByteArray extensionType) {
        this.extensionType = extensionType;
    }

    public void setExtensionLength(ModifiableInteger extensionLength) {
        this.extensionLength = extensionLength;
    }

    public void setExtensionBytes(ModifiableByteArray extensionBytes) {
        this.extensionBytes = extensionBytes;
    }

    public ExtensionType getExtensionTypeConstant() {
        return extensionTypeConstant;
    }

    public abstract ExtensionHandler<? extends ExtensionMessage> getExtensionHandler();

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (extensionType == null || extensionType.getValue() == null) {
            sb.append("\n    Extension type: null");
        } else {
            sb.append("\n    Extension type: ").append(ArrayConverter.bytesToHexString(extensionType.getValue()));
        }
        if (extensionLength == null || extensionLength.getValue() == null) {
            sb.append("\n    Extension length: null");

        } else {
            sb.append("\n    Extension length: ").append(extensionLength.getValue());
        }
        return sb.toString();
    }
}

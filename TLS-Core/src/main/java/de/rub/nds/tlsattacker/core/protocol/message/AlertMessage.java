/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.StructuredLogValueBuilder;
import de.rub.nds.tlsattacker.core.protocol.handler.AlertHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.AlertParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.AlertPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.AlertSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.InputStream;
import java.util.Objects;

@XmlRootElement(name = "Alert")
public class AlertMessage extends ProtocolMessage {

    /** config array used to configure alert message */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] config;
    /** alert level */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByte level;

    /** alert description */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByte description;

    public AlertMessage() {
        super();
        this.protocolMessageType = ProtocolMessageType.ALERT;
    }

    public ModifiableByte getLevel() {
        return level;
    }

    public void setLevel(byte level) {
        this.level = ModifiableVariableFactory.safelySetValue(this.level, level);
    }

    public void setLevel(ModifiableByte level) {
        this.level = level;
    }

    public ModifiableByte getDescription() {
        return description;
    }

    public void setDescription(byte description) {
        this.description = ModifiableVariableFactory.safelySetValue(this.description, description);
    }

    public void setDescription(ModifiableByte description) {
        this.description = description;
    }

    public byte[] getConfig() {
        return config;
    }

    public void setConfig(byte[] config) {
        this.config = config;
    }

    public void setConfig(AlertLevel level, AlertDescription description) {
        config = new byte[2];
        config[0] = level.getValue();
        config[1] = description.getValue();
    }

    @Override
    protected void addStructuredLogFields(StructuredLogValueBuilder builder) {
        super.addStructuredLogFields(builder);
        Byte levelValue = level == null ? null : level.getValue();
        AlertLevel resolvedLevel =
                levelValue == null ? null : AlertLevel.getAlertLevel(levelValue);
        if (resolvedLevel != null) {
            builder.add("level", resolvedLevel);
        } else {
            builder.addHex("level", levelValue == null ? null : new byte[] {levelValue});
        }
        Byte descriptionValue = description == null ? null : description.getValue();
        AlertDescription resolvedDescription =
                descriptionValue == null
                        ? null
                        : AlertDescription.getAlertDescription(descriptionValue);
        if (resolvedDescription != null) {
            builder.add("description", resolvedDescription);
        } else {
            builder.addHex(
                    "description",
                    descriptionValue == null ? null : new byte[] {descriptionValue});
        }
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder("AlertMessage:");
        builder.append("\n  Level: ").append(level == null ? null : level.getValue());
        builder.append("\n  Description: ")
                .append(description == null ? null : description.getValue());
        return builder.toString();
    }

    @Override
    public String toCompactString() {
        AlertLevel resolvedLevel =
                level == null || level.getValue() == null
                        ? null
                        : AlertLevel.getAlertLevel(level.getValue());
        AlertDescription resolvedDescription =
                description == null || description.getValue() == null
                        ? null
                        : AlertDescription.getAlertDescription(description.getValue());
        if (resolvedLevel == null && resolvedDescription == null) {
            return "ALERT";
        }
        return "ALERT ("
                + (resolvedLevel == null ? "UNKNOWN_LEVEL" : resolvedLevel)
                + ", "
                + (resolvedDescription == null ? "UNKNOWN_DESCRIPTION" : resolvedDescription)
                + ")";
    }

    @Override
    public String toShortString() {
        return "ALERT";
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof AlertMessage)) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        AlertMessage alert = (AlertMessage) obj;
        if (alert.getLevel() != null
                && alert.getDescription() != null
                && this.getLevel() != null
                && this.getDescription() != null) {

            return (Objects.equals(alert.getLevel().getValue(), this.getLevel().getValue()))
                    && (Objects.equals(
                            alert.getDescription().getValue(), this.getDescription().getValue()));
        } else {
            // If level is null we do not compare the values
            if (this.getLevel() == null || alert.getLevel() == null) {
                return (Objects.equals(
                        alert.getDescription().getValue(), this.getDescription().getValue()));
            } else {
                return (Objects.equals(alert.getLevel().getValue(), this.getLevel().getValue()));
            }
        }
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 73 * hash + Objects.hashCode(this.level.getValue());
        hash = 73 * hash + Objects.hashCode(this.description.getValue());
        return hash;
    }

    @Override
    public AlertHandler getHandler(TlsContext tlsContext) {
        return new AlertHandler(tlsContext);
    }

    @Override
    public AlertParser getParser(TlsContext tlsContext, InputStream stream) {
        return new AlertParser(stream);
    }

    @Override
    public AlertPreparator getPreparator(TlsContext tlsContext) {
        return new AlertPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public AlertSerializer getSerializer(TlsContext tlsContext) {
        return new AlertSerializer(this);
    }
}

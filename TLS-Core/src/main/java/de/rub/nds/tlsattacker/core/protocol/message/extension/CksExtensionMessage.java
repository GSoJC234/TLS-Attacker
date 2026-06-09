/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.CksExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CksExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CksExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CksExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** Certificate Key Selection extension used by X9.146 implementations. */
@XmlRootElement(name = "CksExtension")
public class CksExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty private ModifiableByteArray cksSigSpecBytes;

    public CksExtensionMessage() {
        super(ExtensionType.CKS);
    }

    public ModifiableByteArray getCksSigSpecBytes() {
        return cksSigSpecBytes;
    }

    public void setCksSigSpecBytes(ModifiableByteArray cksSigSpecBytes) {
        this.cksSigSpecBytes = cksSigSpecBytes;
    }

    public void setCksSigSpecBytes(byte[] cksSigSpecBytes) {
        this.cksSigSpecBytes =
                ModifiableVariableFactory.safelySetValue(this.cksSigSpecBytes, cksSigSpecBytes);
    }

    @Override
    public CksExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new CksExtensionParser(stream, tlsContext);
    }

    @Override
    public CksExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new CksExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public CksExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new CksExtensionSerializer(this);
    }

    @Override
    public CksExtensionHandler getHandler(TlsContext tlsContext) {
        return new CksExtensionHandler(tlsContext);
    }
}

/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer;

import java.io.InputStream;

import de.rub.nds.tlsattacker.core.layer.context.LayerContext;
import de.rub.nds.tlsattacker.core.protocol.Handler;
import de.rub.nds.tlsattacker.core.protocol.Parser;
import de.rub.nds.tlsattacker.core.protocol.Preparator;
import de.rub.nds.tlsattacker.core.protocol.Serializer;

/**
 * All protocol messages are abstracted with the DataContainer interface. For TLS-Attacker to work with data it only
 * needs to know how to parse, prepare, serialize and handle the message. All messages must therefore provide this
 * functionality.
 *
 */
public interface DataContainer<Container extends DataContainer, Context extends LayerContext> {


    public Parser<Container> getParser(Context context, InputStream stream);

    public Preparator<Container> getPreparator(Context context);

    public Serializer<Container> getSerializer(Context context);

    public Handler<Container> getHandler(Context context);

    public default boolean isRequired() {
        return true;
    }
}

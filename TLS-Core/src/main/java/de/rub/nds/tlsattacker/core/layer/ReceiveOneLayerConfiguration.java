/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import java.util.List;
import java.util.stream.Collectors;

public class ReceiveOneLayerConfiguration<Container extends DataContainer<?>>
        extends SpecificReceiveLayerConfiguration<Container> {
    public ReceiveOneLayerConfiguration(LayerType layerType, List<Container> containers) {
        super(layerType, containers);
    }

    public ReceiveOneLayerConfiguration(LayerType layerType, Container... containers) {
        super(layerType, containers);
    }

    @Override
    public boolean isProcessTrailingContainers() {
        return false;
    }

    @Override
    public boolean executedAsPlanned(List<Container> list) {
        return list.size() == 1;
    }

    @Override
    public String toCompactString() {
        return "("
                + getLayerType().getName()
                + ") ReceiveOne:"
                + getContainerList().stream()
                        .map(DataContainer::toCompactString)
                        .collect(Collectors.joining(","));
    }
}

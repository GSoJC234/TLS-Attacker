/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.transport.udp;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.udp.stream.UdpInputStream;
import de.rub.nds.tlsattacker.transport.udp.stream.UdpOutputStream;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;

public class ClientUdpTransportHandler extends UdpTransportHandler {

    private final String hostname;

    public ClientUdpTransportHandler(Connection connection) {
        super(connection.getFirstTimeout(), connection.getTimeout(), ConnectionEndType.CLIENT, false);
        this.hostname = connection.getHostname();
        this.port = connection.getPort();
    }

    public ClientUdpTransportHandler(long firstTimeout, long timeout, String hostname, int port) {
        super(firstTimeout, timeout, ConnectionEndType.CLIENT, false);
        this.hostname = hostname;
        this.port = port;
    }

    @Override
    public void initialize() throws IOException {
        socket = new DatagramSocket();
        socket.connect(new InetSocketAddress(hostname, port));
        socket.setSoTimeout((int) getTimeout());
        srcPort = socket.getLocalPort();
        dstPort = socket.getPort();
        setStreams(new PushbackInputStream(new UdpInputStream(socket, false)), new UdpOutputStream(socket));
    }

    public int getLocalPort() throws IOException {
        if (socket.isConnected()) {
            return socket.getLocalPort();
        }
        throw new IOException("Cannot retrieve local Port. Socket not connected");
    }
}

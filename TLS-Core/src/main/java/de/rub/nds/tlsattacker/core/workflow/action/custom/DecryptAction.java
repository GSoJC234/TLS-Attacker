/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.protocol.MessageFactory;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "DecryptAction")
public class DecryptAction extends ConnectionBoundAction {

    @XmlTransient private List<ProtocolMessage> message_container;
    @XmlTransient private List<Record> record_container;
    @XmlTransient private List<KeySet> keyset_container;

    public DecryptAction() {}

    public DecryptAction(String alias) {
        super(alias);
    }

    public DecryptAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public DecryptAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public void setProtocolMessage(List<ProtocolMessage> message_container) {
        this.message_container = message_container;
    }

    public void setRecordMessage(List<Record> record_container) {
        this.record_container = record_container;
    }

    public void setKeySet(List<KeySet> keyset_container) {
        this.keyset_container = keyset_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext context = state.getTlsContext(getConnectionAlias());
        Record record = record_container.get(0);
        KeySet keyset = keyset_container.get(0);

        RecordCipher cipher = RecordCipherFactory.getRecordCipher(context, keyset, false);
        try {
            cipher.decrypt(record);
            ProtocolMessage message = null;
            byte[] decryptedMessage = record.getCleanProtocolMessageBytes().getValue();
            byte[] parseContents = null;
            if (ProtocolMessageType.getContentType(record.getContentType().getValue())
                    == ProtocolMessageType.ALERT) {
                message = new AlertMessage();
                parseContents = decryptedMessage;

                message.getParser(context, new ByteArrayInputStream(parseContents));
                Preparator preparator = message.getPreparator(context);
                preparator.prepareAfterParse();
                Handler handler = message.getHandler(context);
                handler.adjustContext(message);
            } else if (ProtocolMessageType.getContentType(record.getContentType().getValue())
                    == ProtocolMessageType.HANDSHAKE) {
                byte type = decryptedMessage[0];
                byte[] lengthByte = new byte[3];
                lengthByte[0] = decryptedMessage[1];
                lengthByte[1] = decryptedMessage[2];
                lengthByte[2] = decryptedMessage[3];
                message =
                        (HandshakeMessage)
                                MessageFactory.generateHandshakeMessage(
                                        HandshakeMessageType.getMessageType(type), context);
                ((HandshakeMessage) message).setType(type);
                ((HandshakeMessage) message)
                        .setMessageContent(
                                Arrays.copyOfRange(decryptedMessage, 4, decryptedMessage.length));
                ((HandshakeMessage) message).setCompleteResultingMessage(decryptedMessage);
                parseContents = ((HandshakeMessage) message).getMessageContent().getValue();

                HandshakeMessageHandler handler =
                        (HandshakeMessageHandler) message.getHandler(context);
                handler.adjustContext(message);
                handler.updateDigest(message, false);
            }

            message_container.remove(0);
            message_container.add(message);
        } catch (CryptoException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void reset() {}

    @Override
    public boolean executedAsPlanned() {
        return false;
    }
}

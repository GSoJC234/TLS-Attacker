/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.protocol.handler.FinishedHandler;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.record.serializer.RecordSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "EncryptAction")
public class EncryptAction extends ConnectionBoundAction {

    @XmlTransient private List<Record> record_container;
    @XmlTransient private List<KeySet> keySet_container;

    public EncryptAction() {}

    public EncryptAction(String alias) {
        super(alias);
    }

    public EncryptAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public EncryptAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public void setRecord(List<Record> record_container) {
        this.record_container = record_container;
    }

    public void setKeySet(List<KeySet> ketSet_container) {
        this.keySet_container = ketSet_container;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        if (record_container == null || record_container.isEmpty()) {
            throw new ActionExecutionException("EncryptAction: record_container is empty");
        }
        Record record = record_container.get(0);
        TlsContext context = state.getTlsContext(getConnectionAlias());

        RecordLayer recordLayer = context.getRecordLayer();
        byte[] connectionId =
                recordLayer
                        .getEncryptor()
                        .getRecordCipher(recordLayer.getWriteEpoch())
                        .getState()
                        .getConnectionId();
        if (connectionId != null) {
            record.setConnectionId(connectionId);
        }

        // 암호화 수행
        record.prepareComputations();
        Encryptor encryptor = recordLayer.getEncryptor();
        encryptor.encrypt(record); // protocolMessageBytes(암호문) 채워짐

        // TLS 1.3: Finished를 '보낸 직후' write 키를 애플리케이션 키로 전환
        boolean isTls13 = context.getChooser().getSelectedProtocolVersion().isTLS13();
        boolean innerIsHandshake =
                record.getContentMessageType() == ProtocolMessageType.HANDSHAKE;

        byte[] clean = (record.getCleanProtocolMessageBytes() != null)
                ? record.getCleanProtocolMessageBytes().getValue() : null;

        if (isTls13 && innerIsHandshake && clean != null && clean.length > 0) {
            int hsType = clean[0] & 0xFF; // HandshakeType 첫 바이트
            if (hsType == 0x14 /* Finished */) {
                new FinishedHandler(context).adjustContextAfterSerialize(new FinishedMessage());
            }
        }

        // 최종 직렬화
        if (record.getProtocolMessageBytes() == null
                || record.getProtocolMessageBytes().getValue() == null) {
            throw new ActionExecutionException("EncryptAction: protocolMessageBytes is null");
        }
        RecordSerializer serializer = new RecordSerializer(record);
        record.setLength(record.getProtocolMessageBytes().getValue().length);
        record.setCompleteRecordBytes(serializer.serialize());

        setExecuted(true);
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    @Override
    public boolean executedAsPlanned() {
        return true;
    }
}

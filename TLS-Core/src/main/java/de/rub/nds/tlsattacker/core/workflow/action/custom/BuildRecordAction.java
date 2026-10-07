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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.serializer.RecordSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "BuildRecordAction")
public class BuildRecordAction extends ConnectionBoundAction {

    @XmlTransient private List<Record> record_container = null;

    @XmlTransient private List<ProtocolMessageType> record_type_container = null;
    @XmlTransient private List<ProtocolVersion> version_container = null;
    @XmlTransient private byte[] protocol_version_bytes = null;
    @XmlTransient private List<ProtocolMessage> message_container = null;
    @XmlTransient private List<Integer> message_length = null;


    public BuildRecordAction() {super();}

    public BuildRecordAction(String alias) {super(alias);}

    public BuildRecordAction(Set<ActionOption> actionOptions, String alias){
        super(actionOptions, alias);
        this.connectionAlias = alias;
    }

    public BuildRecordAction(Set<ActionOption> actionOptions) { super(actionOptions);}

    public BuildRecordAction(String alias, List<Record> record_container) {
        super(alias);
        this.record_container = record_container;
    }

    public void setProtocolMessageType(List<ProtocolMessageType> record_type_container) {
        this.record_type_container = record_type_container;
    }

    public void setProtocolVersion(List<ProtocolVersion> version_container) {
        this.version_container = version_container;
    }

    public void setProtocolVersionBytes(byte[] protocolVersionBytes) {
        if (protocolVersionBytes == null || protocolVersionBytes.length != RecordByteLength.PROTOCOL_VERSION) {
            throw new IllegalArgumentException("Record protocol version must be exactly 2 bytes");
        }
        this.protocol_version_bytes = protocolVersionBytes.clone();
    }

    public void setProtocolMessage(List<ProtocolMessage> message_container) {
        this.message_container = message_container;
    }

    public void setProtocolMessageLength(List<Integer> message_length) {
        this.message_length = message_length;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext ctx = state.getTlsContext(getConnectionAlias());

        if (message_container == null || message_container.isEmpty()) {
            throw new ActionExecutionException("BuildRecordAction: message_container is empty");
        }
        if (record_type_container == null || record_type_container.isEmpty()) {
            throw new ActionExecutionException("BuildRecordAction: record_type_container is empty");
        }
        if (record_container == null) {
            throw new ActionExecutionException("BuildRecordAction: record_container is null");
        }

        ProtocolMessage message = message_container.get(0);
        ProtocolMessageType requestedMsgType = record_type_container.get(0);

        Record record = new Record();
        boolean isTls13 = ctx.getChooser().getSelectedProtocolVersion().isTLS13();

        // TLS 1.3에서도 ClientHello/ServerHello/HelloRetryRequest는 평문 Handshake로 전송
        boolean isHelloLike =
                (message instanceof ClientHelloMessage) ||
                        (message instanceof ServerHelloMessage) ||
                        (message instanceof HelloRequestMessage);

        ProtocolMessageType msgType = requestedMsgType;
        if (isTls13
                && requestedMsgType == ProtocolMessageType.APPLICATION_DATA
                && message instanceof HandshakeMessage
                && !isHelloLike) {
            msgType = ProtocolMessageType.HANDSHAKE;
        }
        boolean isHandshake = (msgType == ProtocolMessageType.HANDSHAKE);

        // 보호가 필요한 구간? → TLS1.3 && Handshake && !Hello류 (EE/Cert/Finished/NST 등)
        boolean needsProtection = isTls13 && isHandshake && !isHelloLike;

        if (needsProtection) {
            // === TLS 1.3 보호 구간: inner type source와 clean bytes만 세팅 ===
            // RecordAEADCipher가 암호화 후 outer content type을 application_data로 설정한다.
            record.setShouldPrepare(false); // 암호화/직렬화는 EncryptAction에서
            record.setContentType(msgType.getValue());
            record.setContentMessageType(msgType);
            if (protocol_version_bytes != null) {
                record.setProtocolVersion(protocol_version_bytes.clone());
            } else {
                record.setProtocolVersion(ProtocolVersion.TLS12.getValue());            // 0x0303
            }
            record.setCleanProtocolMessageBytes(message.getCompleteResultingMessage());
        } else {
            // === 평문 구간(TLS1.2 전체 + TLS1.3의 CH/SH/HRR 등): 기존 방식 그대로 직렬화 ===
            record.setShouldPrepare(false);
            record.setContentType(msgType.getValue());
            record.setContentMessageType(msgType);

            if (protocol_version_bytes != null) {
                record.setProtocolVersion(protocol_version_bytes.clone());
            } else if (version_container != null && !version_container.isEmpty()) {
                record.setProtocolVersion(version_container.get(0).getValue());
            } else {
                record.setProtocolVersion(ctx.getChooser().getSelectedProtocolVersion().getValue());
            }

            record.setProtocolMessageBytes(message.getCompleteResultingMessage());
            record.setCleanProtocolMessageBytes(message.getCompleteResultingMessage());
            int defaultLen = record.getProtocolMessageBytes().getValue().length;
            if(message_length != null && !message_length.isEmpty()) {
                record.setLength(
                        SizeCalculator.calculate(
                                message_length.get(0),
                                defaultLen,
                                RecordByteLength.RECORD_LENGTH));
            } else {
                record.setLength(defaultLen);
            }

            RecordSerializer serializer = new RecordSerializer(record);
            record.setCompleteRecordBytes(serializer.serialize());
        }

        record_container.add(record);
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

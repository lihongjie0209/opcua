package pubsub

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const maxUADPDynamicPayloadBytes = 65535

// UADPDynamicDataSet carries one opaque DataSetMessage.
type UADPDynamicDataSet struct {
	WriterID uint16
	Message  []byte
}

// UADPDynamicMessage is an unsecured dynamic UADP NetworkMessage envelope.
type UADPDynamicMessage struct {
	PublisherID uint64
	DataSets    []UADPDynamicDataSet
}

// EncodeUADPDynamic encodes a bounded unsecured dynamic UADP envelope.
func EncodeUADPDynamic(message UADPDynamicMessage) ([]byte, error) {
	count := len(message.DataSets)
	if count == 0 || count > 64 {
		return nil, errors.New("dynamic UADP requires 1..64 DataSetMessages")
	}
	sizeTableBytes := 0
	if count > 1 {
		sizeTableBytes = 2 * count
	}
	payloadBytes := sizeTableBytes
	seen := make(map[uint16]struct{}, count)
	for index, dataSet := range message.DataSets {
		if dataSet.WriterID == 0 {
			return nil, fmt.Errorf("dynamic UADP writer %d has zero ID", index)
		}
		if _, exists := seen[dataSet.WriterID]; exists {
			return nil, fmt.Errorf("dynamic UADP writer %d has duplicate ID", index)
		}
		seen[dataSet.WriterID] = struct{}{}
		length := len(dataSet.Message)
		if length == 0 || length > maxUADPDynamicPayloadBytes || payloadBytes > maxUADPDynamicPayloadBytes-length {
			return nil, fmt.Errorf("dynamic UADP DataSetMessage %d exceeds payload bounds", index)
		}
		payloadBytes += length
	}
	headerBytes := 2 + 8 + 1 + 2*count
	wire := make([]byte, headerBytes+payloadBytes)
	wire[0], wire[1] = 0xd1, 0x03
	binary.LittleEndian.PutUint64(wire[2:], message.PublisherID)
	wire[10] = byte(count)
	for index, dataSet := range message.DataSets {
		binary.LittleEndian.PutUint16(wire[11+2*index:], dataSet.WriterID)
	}
	offset := headerBytes
	if count > 1 {
		for index, dataSet := range message.DataSets {
			binary.LittleEndian.PutUint16(wire[offset+2*index:], uint16(len(dataSet.Message)))
		}
		offset += sizeTableBytes
	}
	for _, dataSet := range message.DataSets {
		copy(wire[offset:], dataSet.Message)
		offset += len(dataSet.Message)
	}
	return wire, nil
}

// DecodeUADPDynamic decodes a bounded unsecured dynamic UADP envelope.
func DecodeUADPDynamic(wire []byte) (UADPDynamicMessage, error) {
	if len(wire) < 14 || len(wire) > 2+8+1+2*64+maxUADPDynamicPayloadBytes {
		return UADPDynamicMessage{}, errors.New("dynamic UADP NetworkMessage size is invalid")
	}
	if wire[0] != 0xd1 || wire[1] != 0x03 {
		return UADPDynamicMessage{}, errors.New("unsupported dynamic UADP version or security flags")
	}
	count := int(wire[10])
	if count == 0 || count > 64 {
		return UADPDynamicMessage{}, errors.New("dynamic UADP DataSetMessage count is invalid")
	}
	headerBytes := 2 + 8 + 1 + 2*count
	if len(wire) <= headerBytes {
		return UADPDynamicMessage{}, errors.New("truncated dynamic UADP payload header")
	}
	result := UADPDynamicMessage{PublisherID: binary.LittleEndian.Uint64(wire[2:]), DataSets: make([]UADPDynamicDataSet, count)}
	seen := make(map[uint16]struct{}, count)
	for index := range result.DataSets {
		writerID := binary.LittleEndian.Uint16(wire[11+2*index:])
		if writerID == 0 {
			return UADPDynamicMessage{}, fmt.Errorf("dynamic UADP writer %d has zero ID", index)
		}
		if _, exists := seen[writerID]; exists {
			return UADPDynamicMessage{}, fmt.Errorf("dynamic UADP writer %d has duplicate ID", index)
		}
		seen[writerID] = struct{}{}
		result.DataSets[index].WriterID = writerID
	}
	payload := wire[headerBytes:]
	if len(payload) > maxUADPDynamicPayloadBytes {
		return UADPDynamicMessage{}, errors.New("dynamic UADP payload exceeds 65535 bytes")
	}
	if count == 1 {
		result.DataSets[0].Message = append([]byte(nil), payload...)
		return result, nil
	}
	sizeTableBytes := 2 * count
	if len(payload) <= sizeTableBytes {
		return UADPDynamicMessage{}, errors.New("truncated dynamic UADP size table or DataSetMessages")
	}
	lengths := make([]int, count)
	total := sizeTableBytes
	for index := range lengths {
		length := int(binary.LittleEndian.Uint16(payload[2*index:]))
		if length == 0 || total > maxUADPDynamicPayloadBytes-length {
			return UADPDynamicMessage{}, fmt.Errorf("dynamic UADP DataSetMessage %d has invalid length", index)
		}
		lengths[index] = length
		total += length
	}
	if total != len(payload) {
		return UADPDynamicMessage{}, errors.New("dynamic UADP DataSetMessage lengths do not exhaust payload")
	}
	offset := sizeTableBytes
	for index, length := range lengths {
		result.DataSets[index].Message = append([]byte(nil), payload[offset:offset+length]...)
		offset += length
	}
	return result, nil
}

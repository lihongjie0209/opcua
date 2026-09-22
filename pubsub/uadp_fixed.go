package pubsub

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const MaxUADPMessageBytes = 1 << 20

// UADPFixedMessage contains one unsecured Annex A.2.1.4 fixed-layout network
// header and an opaque, caller-described DataSet payload.
type UADPFixedMessage struct {
	PublisherIDBits      uint8
	PublisherID          uint64
	WriterGroupID        uint16
	GroupVersion         uint32
	NetworkMessageNumber uint16
	SequenceNumber       uint16
	Payload              []byte
}

// DecodeUADPFixed decodes the supported fixed-layout header and returns its
// exact size. The returned payload never aliases wire.
func DecodeUADPFixed(wire []byte) (UADPFixedMessage, int, error) {
	if len(wire) > MaxUADPMessageBytes {
		return UADPFixedMessage{}, 0, errors.New("UADP NetworkMessage exceeds size limit")
	}
	if len(wire) < 2 || wire[0] != 0xb1 {
		return UADPFixedMessage{}, 0, errors.New("unsupported UADP version or network flags")
	}
	var result UADPFixedMessage
	var publisherBytes int
	switch wire[1] {
	case 0x01:
		result.PublisherIDBits, publisherBytes = 16, 2
	case 0x03:
		result.PublisherIDBits, publisherBytes = 64, 8
	default:
		return UADPFixedMessage{}, 0, errors.New("unsupported UADP extended flags or PublisherId type")
	}
	headerLen := 2 + publisherBytes + 1 + 2 + 4 + 2 + 2
	if len(wire) <= headerLen {
		return UADPFixedMessage{}, 0, errors.New("truncated UADP fixed header or empty payload")
	}
	offset := 2
	if publisherBytes == 2 {
		result.PublisherID = uint64(binary.LittleEndian.Uint16(wire[offset:]))
	} else {
		result.PublisherID = binary.LittleEndian.Uint64(wire[offset:])
	}
	offset += publisherBytes
	if wire[offset] != 0x0f {
		return UADPFixedMessage{}, 0, errors.New("unsupported UADP group flags")
	}
	offset++
	result.WriterGroupID = binary.LittleEndian.Uint16(wire[offset:])
	offset += 2
	result.GroupVersion = binary.LittleEndian.Uint32(wire[offset:])
	offset += 4
	result.NetworkMessageNumber = binary.LittleEndian.Uint16(wire[offset:])
	if result.NetworkMessageNumber == 0 {
		return UADPFixedMessage{}, 0, errors.New("UADP NetworkMessageNumber must be nonzero")
	}
	offset += 2
	result.SequenceNumber = binary.LittleEndian.Uint16(wire[offset:])
	result.Payload = append([]byte(nil), wire[headerLen:]...)
	return result, headerLen, nil
}

// EncodeUADPFixed encodes the supported fixed-layout header and opaque
// DataSet payload. Payload interpretation remains metadata-driven.
func EncodeUADPFixed(message UADPFixedMessage) ([]byte, error) {
	var publisherBytes int
	var extendedFlags byte
	switch message.PublisherIDBits {
	case 16:
		if message.PublisherID > 0xffff {
			return nil, errors.New("UInt16 UADP PublisherId exceeds range")
		}
		publisherBytes, extendedFlags = 2, 0x01
	case 64:
		publisherBytes, extendedFlags = 8, 0x03
	default:
		return nil, fmt.Errorf("unsupported UADP PublisherId width %d", message.PublisherIDBits)
	}
	if message.NetworkMessageNumber == 0 {
		return nil, errors.New("UADP NetworkMessageNumber must be nonzero")
	}
	headerLen := 2 + publisherBytes + 1 + 2 + 4 + 2 + 2
	if len(message.Payload) == 0 || len(message.Payload) > MaxUADPMessageBytes-headerLen {
		return nil, errors.New("UADP payload is empty or NetworkMessage exceeds size limit")
	}
	wire := make([]byte, headerLen+len(message.Payload))
	wire[0], wire[1] = 0xb1, extendedFlags
	offset := 2
	if publisherBytes == 2 {
		binary.LittleEndian.PutUint16(wire[offset:], uint16(message.PublisherID))
	} else {
		binary.LittleEndian.PutUint64(wire[offset:], message.PublisherID)
	}
	offset += publisherBytes
	wire[offset] = 0x0f
	offset++
	binary.LittleEndian.PutUint16(wire[offset:], message.WriterGroupID)
	offset += 2
	binary.LittleEndian.PutUint32(wire[offset:], message.GroupVersion)
	offset += 4
	binary.LittleEndian.PutUint16(wire[offset:], message.NetworkMessageNumber)
	offset += 2
	binary.LittleEndian.PutUint16(wire[offset:], message.SequenceNumber)
	copy(wire[headerLen:], message.Payload)
	return wire, nil
}

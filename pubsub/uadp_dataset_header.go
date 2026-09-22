package pubsub

import (
	"encoding/binary"
	"errors"
)

// UADPDataSetMessageType identifies a supported Variant DataSetMessage body.
type UADPDataSetMessageType uint8

const (
	UADPDataSetKeyFrame       UADPDataSetMessageType = 0
	UADPDataSetDeltaFrame     UADPDataSetMessageType = 1
	UADPDataSetEvent          UADPDataSetMessageType = 2
	UADPDataSetKeepAlive      UADPDataSetMessageType = 3
	UADPDataSetActionRequest  UADPDataSetMessageType = 5
	UADPDataSetActionResponse UADPDataSetMessageType = 6
)

// UADPDataSetHeader preserves the optional header values exactly. Timestamp
// is encoded as OPC UA 100 ns ticks. Action fields are present only for
// ActionRequest and ActionResponse messages.
type UADPDataSetHeader struct {
	Type           UADPDataSetMessageType
	SequenceNumber *uint16
	Timestamp      *uint64
	PicoSeconds    *uint16
	Status         *uint16
	MajorVersion   *uint32
	MinorVersion   *uint32
	ActionTargetID uint16
	RequestID      uint16
	ActionState    uint8
}

func supportedUADPDataSetType(kind UADPDataSetMessageType) bool {
	switch kind {
	case UADPDataSetKeyFrame, UADPDataSetDeltaFrame, UADPDataSetEvent,
		UADPDataSetKeepAlive, UADPDataSetActionRequest, UADPDataSetActionResponse:
		return true
	default:
		return false
	}
}

// EncodeUADPDataSetHeader encodes a strict Variant DataSetMessage header.
func EncodeUADPDataSetHeader(header UADPDataSetHeader) ([]byte, error) {
	if !supportedUADPDataSetType(header.Type) {
		return nil, errors.New("unsupported UADP DataSetMessage type")
	}
	if header.PicoSeconds != nil && (header.Timestamp == nil || *header.PicoSeconds >= 10000) {
		return nil, errors.New("UADP picoseconds require timestamp and range 0..9999")
	}
	action := header.Type == UADPDataSetActionRequest || header.Type == UADPDataSetActionResponse
	if action {
		if header.ActionState > 2 {
			return nil, errors.New("invalid UADP ActionState")
		}
	} else if header.ActionTargetID != 0 || header.RequestID != 0 || header.ActionState != 0 {
		return nil, errors.New("non-Action DataSetMessage carries Action header")
	}
	flags1 := byte(1)
	flags2 := byte(header.Type)
	if header.SequenceNumber != nil {
		flags1 |= 0x08
	}
	if header.Status != nil {
		flags1 |= 0x10
	}
	if header.MajorVersion != nil {
		flags1 |= 0x20
	}
	if header.MinorVersion != nil {
		flags1 |= 0x40
	}
	if header.Timestamp != nil {
		flags2 |= 0x10
	}
	if header.PicoSeconds != nil {
		flags2 |= 0x20
	}
	if flags2 != 0 {
		flags1 |= 0x80
	}
	wire := make([]byte, 0, 29)
	wire = append(wire, flags1)
	if flags2 != 0 {
		wire = append(wire, flags2)
	}
	if header.SequenceNumber != nil {
		wire = binary.LittleEndian.AppendUint16(wire, *header.SequenceNumber)
	}
	if header.Timestamp != nil {
		wire = binary.LittleEndian.AppendUint64(wire, *header.Timestamp)
	}
	if header.PicoSeconds != nil {
		wire = binary.LittleEndian.AppendUint16(wire, *header.PicoSeconds)
	}
	if header.Status != nil {
		wire = binary.LittleEndian.AppendUint16(wire, *header.Status)
	}
	if header.MajorVersion != nil {
		wire = binary.LittleEndian.AppendUint32(wire, *header.MajorVersion)
	}
	if header.MinorVersion != nil {
		wire = binary.LittleEndian.AppendUint32(wire, *header.MinorVersion)
	}
	if action {
		wire = binary.LittleEndian.AppendUint16(wire, header.ActionTargetID)
		wire = binary.LittleEndian.AppendUint16(wire, header.RequestID)
		wire = append(wire, header.ActionState)
	}
	return wire, nil
}

// DecodeUADPDataSetHeader decodes one header prefix and returns bytes consumed.
// The caller remains responsible for validating the following message body.
func DecodeUADPDataSetHeader(wire []byte) (UADPDataSetHeader, int, error) {
	if len(wire) == 0 || len(wire) > maxUADPDynamicPayloadBytes {
		return UADPDataSetHeader{}, 0, errors.New("UADP DataSetMessage size is invalid")
	}
	flags1 := wire[0]
	if flags1&0x01 == 0 || flags1&0x06 != 0 {
		return UADPDataSetHeader{}, 0, errors.New("invalid or unsupported UADP DataSetFlags1")
	}
	offset := 1
	flags2 := byte(0)
	if flags1&0x80 != 0 {
		if offset == len(wire) {
			return UADPDataSetHeader{}, 0, errors.New("truncated UADP DataSetFlags2")
		}
		flags2 = wire[offset]
		offset++
		if flags2 == 0 || flags2&0xc0 != 0 || flags2&0x20 != 0 && flags2&0x10 == 0 {
			return UADPDataSetHeader{}, 0, errors.New("invalid UADP DataSetFlags2")
		}
	}
	header := UADPDataSetHeader{Type: UADPDataSetMessageType(flags2 & 0x0f)}
	if !supportedUADPDataSetType(header.Type) {
		return UADPDataSetHeader{}, 0, errors.New("unsupported UADP DataSetMessage type")
	}
	read := func(size int) ([]byte, error) {
		if len(wire)-offset < size {
			return nil, errors.New("truncated UADP DataSetMessage header")
		}
		part := wire[offset : offset+size]
		offset += size
		return part, nil
	}
	if flags1&0x08 != 0 {
		part, err := read(2)
		if err != nil {
			return UADPDataSetHeader{}, 0, err
		}
		value := binary.LittleEndian.Uint16(part)
		header.SequenceNumber = &value
	}
	if flags2&0x10 != 0 {
		part, err := read(8)
		if err != nil {
			return UADPDataSetHeader{}, 0, err
		}
		value := binary.LittleEndian.Uint64(part)
		header.Timestamp = &value
	}
	if flags2&0x20 != 0 {
		part, err := read(2)
		if err != nil {
			return UADPDataSetHeader{}, 0, err
		}
		value := binary.LittleEndian.Uint16(part)
		if value >= 10000 {
			value = 9999
		}
		header.PicoSeconds = &value
	}
	if flags1&0x10 != 0 {
		part, err := read(2)
		if err != nil {
			return UADPDataSetHeader{}, 0, err
		}
		value := binary.LittleEndian.Uint16(part)
		header.Status = &value
	}
	if flags1&0x20 != 0 {
		part, err := read(4)
		if err != nil {
			return UADPDataSetHeader{}, 0, err
		}
		value := binary.LittleEndian.Uint32(part)
		header.MajorVersion = &value
	}
	if flags1&0x40 != 0 {
		part, err := read(4)
		if err != nil {
			return UADPDataSetHeader{}, 0, err
		}
		value := binary.LittleEndian.Uint32(part)
		header.MinorVersion = &value
	}
	if header.Type == UADPDataSetActionRequest || header.Type == UADPDataSetActionResponse {
		part, err := read(5)
		if err != nil {
			return UADPDataSetHeader{}, 0, err
		}
		header.ActionTargetID = binary.LittleEndian.Uint16(part)
		header.RequestID = binary.LittleEndian.Uint16(part[2:])
		header.ActionState = part[4]
		if header.ActionState > 2 {
			return UADPDataSetHeader{}, 0, errors.New("invalid UADP ActionState")
		}
	}
	return header, offset, nil
}

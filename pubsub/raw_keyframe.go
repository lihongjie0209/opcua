// Package pubsub contains OPC UA PubSub wire codecs built on the UA Binary codec.
package pubsub

import (
	"bytes"
	"fmt"
	"math"

	"github.com/awcullen/opcua/ua"
)

// RawType is an OPC UA built-in scalar type supported in fixed RawData frames.
type RawType byte

const (
	RawBoolean RawType = 1 + iota
	RawSByte
	RawByte
	RawInt16
	RawUInt16
	RawInt32
	RawUInt32
	RawInt64
	RawUInt64
	RawFloat
	RawDouble
)

// RawField is a typed fixed-layout RawData value.
type RawField struct {
	Type  RawType
	Value any
}

// RawKeyFrame is a scalar RawData DataSetMessage with a sequence number.
type RawKeyFrame struct {
	SequenceNumber uint16
	Status         *uint16
	Fields         []RawField
}

const maxRawMessageBytes = 1 << 20

// EncodeRawKeyFrame encodes a scalar RawData key frame without FieldCount.
func EncodeRawKeyFrame(frame RawKeyFrame) ([]byte, error) {
	if len(frame.Fields) == 0 || len(frame.Fields) > 1024 {
		return nil, fmt.Errorf("RawData requires 1..1024 fields")
	}
	var buf bytes.Buffer
	enc := ua.NewBinaryEncoder(&buf, ua.NewEncodingContext())
	flags := byte(0x0b)
	if frame.Status != nil {
		flags |= 0x10
	}
	if err := enc.WriteByte(flags); err != nil {
		return nil, err
	}
	if err := enc.WriteUInt16(frame.SequenceNumber); err != nil {
		return nil, err
	}
	if frame.Status != nil {
		if err := enc.WriteUInt16(*frame.Status); err != nil {
			return nil, err
		}
	}
	for i, field := range frame.Fields {
		if err := writeRawField(enc, field); err != nil {
			return nil, fmt.Errorf("RawData field %d: %w", i, err)
		}
		if buf.Len() > maxRawMessageBytes {
			return nil, fmt.Errorf("RawData message exceeds size limit")
		}
	}
	return buf.Bytes(), nil
}

func writeRawField(enc *ua.BinaryEncoder, field RawField) error {
	switch field.Type {
	case RawBoolean:
		if v, ok := field.Value.(bool); ok {
			return enc.WriteBoolean(v)
		}
	case RawSByte:
		if v, ok := field.Value.(int8); ok {
			return enc.WriteSByte(v)
		}
	case RawByte:
		if v, ok := field.Value.(uint8); ok {
			return enc.WriteByte(v)
		}
	case RawInt16:
		if v, ok := field.Value.(int16); ok {
			return enc.WriteInt16(v)
		}
	case RawUInt16:
		if v, ok := field.Value.(uint16); ok {
			return enc.WriteUInt16(v)
		}
	case RawInt32:
		if v, ok := field.Value.(int32); ok {
			return enc.WriteInt32(v)
		}
	case RawUInt32:
		if v, ok := field.Value.(uint32); ok {
			return enc.WriteUInt32(v)
		}
	case RawInt64:
		if v, ok := field.Value.(int64); ok {
			return enc.WriteInt64(v)
		}
	case RawUInt64:
		if v, ok := field.Value.(uint64); ok {
			return enc.WriteUInt64(v)
		}
	case RawFloat:
		if v, ok := field.Value.(float32); ok {
			if math.IsNaN(float64(v)) {
				v = math.Float32frombits(0xffc00000)
			}
			return enc.WriteFloat(v)
		}
	case RawDouble:
		if v, ok := field.Value.(float64); ok {
			if math.IsNaN(v) {
				v = math.Float64frombits(0xfff8000000000000)
			}
			return enc.WriteDouble(v)
		}
	}
	return fmt.Errorf("unsupported RawData type or value mismatch: %d", field.Type)
}

// DecodeRawKeyFrame decodes ordered scalar fields and returns consumed bytes.
func DecodeRawKeyFrame(wire []byte, metadata []RawType) (RawKeyFrame, int, error) {
	if len(wire) > maxRawMessageBytes || len(metadata) == 0 || len(metadata) > 1024 || len(wire) < 3 {
		return RawKeyFrame{}, 0, fmt.Errorf("invalid RawData size or metadata")
	}
	reader := bytes.NewReader(wire)
	dec := ua.NewBinaryDecoder(reader, ua.NewEncodingContext())
	var flags byte
	if err := dec.ReadByte(&flags); err != nil || flags != 0x0b && flags != 0x1b {
		return RawKeyFrame{}, 0, fmt.Errorf("unsupported RawData flags")
	}
	frame := RawKeyFrame{Fields: make([]RawField, len(metadata))}
	if err := dec.ReadUInt16(&frame.SequenceNumber); err != nil {
		return RawKeyFrame{}, 0, err
	}
	if flags&0x10 != 0 {
		var status uint16
		if err := dec.ReadUInt16(&status); err != nil {
			return RawKeyFrame{}, 0, err
		}
		frame.Status = &status
	}
	for i, typ := range metadata {
		v, err := readRawField(dec, typ)
		if err != nil {
			return RawKeyFrame{}, 0, fmt.Errorf("RawData field %d: %w", i, err)
		}
		frame.Fields[i] = RawField{Type: typ, Value: v}
	}
	return frame, len(wire) - reader.Len(), nil
}

func readRawField(dec *ua.BinaryDecoder, typ RawType) (any, error) {
	switch typ {
	case RawBoolean:
		var v bool
		err := dec.ReadBoolean(&v)
		return v, err
	case RawSByte:
		var v int8
		err := dec.ReadSByte(&v)
		return v, err
	case RawByte:
		var v byte
		err := dec.ReadByte(&v)
		return v, err
	case RawInt16:
		var v int16
		err := dec.ReadInt16(&v)
		return v, err
	case RawUInt16:
		var v uint16
		err := dec.ReadUInt16(&v)
		return v, err
	case RawInt32:
		var v int32
		err := dec.ReadInt32(&v)
		return v, err
	case RawUInt32:
		var v uint32
		err := dec.ReadUInt32(&v)
		return v, err
	case RawInt64:
		var v int64
		err := dec.ReadInt64(&v)
		return v, err
	case RawUInt64:
		var v uint64
		err := dec.ReadUInt64(&v)
		return v, err
	case RawFloat:
		var v float32
		err := dec.ReadFloat(&v)
		return v, err
	case RawDouble:
		var v float64
		err := dec.ReadDouble(&v)
		return v, err
	default:
		return nil, fmt.Errorf("unsupported RawData type: %d", typ)
	}
}

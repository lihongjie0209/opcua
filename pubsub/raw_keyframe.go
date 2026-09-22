// Package pubsub contains OPC UA PubSub wire codecs built on the UA Binary codec.
package pubsub

import (
	"bytes"
	"fmt"
	"io"
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

const (
	RawString     RawType = 12
	RawByteString RawType = 15
)

// RawField is a typed fixed-layout RawData value.
type RawField struct {
	Type            RawType
	Value           any
	MaxStringLength uint32
	ValueRank       int32
	ArrayDimensions []uint32
}

// RawFieldMeta describes the fixed wire layout of a RawData field.
type RawFieldMeta struct {
	Type            RawType
	MaxStringLength uint32
	ValueRank       int32
	ArrayDimensions []uint32
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
		if field.ValueRank == 1 {
			if err := encodeRawArray(&buf, enc, field); err != nil {
				return nil, fmt.Errorf("RawData field %d: %w", i, err)
			}
			continue
		}
		if field.ValueRank != 0 && field.ValueRank != -1 || len(field.ArrayDimensions) != 0 {
			return nil, fmt.Errorf("RawData field %d has unsupported ValueRank or ArrayDimensions", i)
		}
		if field.Type == RawString || field.Type == RawByteString {
			if field.MaxStringLength == 0 || field.MaxStringLength > maxRawMessageBytes ||
				buf.Len()+4+int(field.MaxStringLength) > maxRawMessageBytes {
				return nil, fmt.Errorf("RawData field %d has invalid maximum length", i)
			}
		}
		if err := writeRawField(enc, field); err != nil {
			return nil, fmt.Errorf("RawData field %d: %w", i, err)
		}
		if field.Type == RawString || field.Type == RawByteString {
			var actual int
			switch v := field.Value.(type) {
			case string:
				actual = len(v)
			case []byte:
				actual = len(v)
			}
			buf.Write(make([]byte, int(field.MaxStringLength)-actual))
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
	case RawString:
		if v, ok := field.Value.(string); ok && len(v) <= int(field.MaxStringLength) {
			return enc.WriteString(v)
		}
	case RawByteString:
		if v, ok := field.Value.([]byte); ok && len(v) <= int(field.MaxStringLength) {
			return enc.WriteByteString(ua.ByteString(v))
		}
	}
	return fmt.Errorf("unsupported RawData type or value mismatch: %d", field.Type)
}

// DecodeRawKeyFrame decodes ordered scalar fields and returns consumed bytes.
func DecodeRawKeyFrame(wire []byte, metadata []RawType) (RawKeyFrame, int, error) {
	fields := make([]RawFieldMeta, len(metadata))
	for i, typ := range metadata {
		fields[i] = RawFieldMeta{Type: typ}
	}
	return DecodeRawKeyFrameWithMetadata(wire, fields)
}

// DecodeRawKeyFrameWithMetadata validates and consumes a metadata-defined layout.
func DecodeRawKeyFrameWithMetadata(wire []byte, metadata []RawFieldMeta) (RawKeyFrame, int, error) {
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
	for i, meta := range metadata {
		var v any
		var err error
		if meta.ValueRank == 1 {
			v, err = decodeRawArray(dec, reader, meta)
		} else if meta.ValueRank != 0 && meta.ValueRank != -1 || len(meta.ArrayDimensions) != 0 {
			return RawKeyFrame{}, 0, fmt.Errorf("RawData field %d has unsupported ValueRank or ArrayDimensions", i)
		} else if meta.Type == RawString || meta.Type == RawByteString {
			v, err = readPaddedString(dec, reader, meta)
		} else {
			if meta.MaxStringLength != 0 {
				return RawKeyFrame{}, 0, fmt.Errorf("RawData field %d has unexpected maximum length", i)
			}
			v, err = readRawField(dec, meta.Type)
		}
		if err != nil {
			return RawKeyFrame{}, 0, fmt.Errorf("RawData field %d: %w", i, err)
		}
		frame.Fields[i] = RawField{Type: meta.Type, Value: v, MaxStringLength: meta.MaxStringLength,
			ValueRank: meta.ValueRank, ArrayDimensions: append([]uint32(nil), meta.ArrayDimensions...)}
	}
	return frame, len(wire) - reader.Len(), nil
}

func readPaddedString(dec *ua.BinaryDecoder, reader *bytes.Reader, meta RawFieldMeta) (any, error) {
	return readPaddedStringValue(dec, reader, meta, true)
}

func readPaddedStringArrayElement(dec *ua.BinaryDecoder, reader *bytes.Reader, meta RawFieldMeta) (any, error) {
	return readPaddedStringValue(dec, reader, meta, false)
}

func readPaddedStringValue(dec *ua.BinaryDecoder, reader *bytes.Reader, meta RawFieldMeta, allowNull bool) (any, error) {
	if meta.MaxStringLength == 0 || meta.MaxStringLength > maxRawMessageBytes ||
		int(meta.MaxStringLength)+4 > reader.Len() {
		return nil, fmt.Errorf("invalid or truncated maximum string length")
	}
	var length int32
	if err := dec.ReadInt32(&length); err != nil {
		return nil, err
	}
	if length < -1 || !allowNull && length < 0 || length > int32(meta.MaxStringLength) {
		return nil, fmt.Errorf("invalid string length")
	}
	actual := int(length)
	if actual < 0 {
		actual = 0
	}
	value := make([]byte, actual)
	if _, err := io.ReadFull(reader, value); err != nil {
		return nil, err
	}
	padding := make([]byte, int(meta.MaxStringLength)-actual)
	if _, err := io.ReadFull(reader, padding); err != nil {
		return nil, err
	}
	for _, b := range padding {
		if b != 0 {
			return nil, fmt.Errorf("nonzero RawData padding")
		}
	}
	if meta.Type == RawString {
		return string(value), nil
	}
	return value, nil
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

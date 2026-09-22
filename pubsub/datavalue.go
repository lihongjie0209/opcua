package pubsub

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/awcullen/opcua/ua"
)

// ExactDataValue preserves optional fields and raw DateTime ticks exactly.
type ExactDataValue struct {
	ValuePresent      bool
	Value             ua.Variant
	StatusCode        *uint32
	SourceTimestamp   *int64
	SourcePicoseconds *uint16
	ServerTimestamp   *int64
	ServerPicoseconds *uint16
}

// EncodeExactDataValue encodes a bounded DataValue without converting its raw
// DateTime ticks through time.Time.
func EncodeExactDataValue(value ExactDataValue) ([]byte, error) {
	var mask byte
	if value.ValuePresent {
		mask |= 1
	}
	if value.StatusCode != nil {
		mask |= 2
	}
	if value.SourceTimestamp != nil {
		mask |= 4
	}
	if value.ServerTimestamp != nil {
		mask |= 8
	}
	if value.SourcePicoseconds != nil {
		mask |= 16
	}
	if value.ServerPicoseconds != nil {
		mask |= 32
	}
	var buf bytes.Buffer
	buf.WriteByte(mask)
	enc := ua.NewBinaryEncoder(&buf, ua.NewEncodingContext())
	if value.ValuePresent {
		if err := enc.WriteVariant(value.Value); err != nil {
			return nil, err
		}
	}
	write := func(v any) error { return enc.Encode(v) }
	if value.StatusCode != nil {
		if err := write(*value.StatusCode); err != nil {
			return nil, err
		}
	}
	if value.SourceTimestamp != nil {
		if err := write(*value.SourceTimestamp); err != nil {
			return nil, err
		}
	}
	if value.SourcePicoseconds != nil {
		if err := write(*value.SourcePicoseconds); err != nil {
			return nil, err
		}
	}
	if value.ServerTimestamp != nil {
		if err := write(*value.ServerTimestamp); err != nil {
			return nil, err
		}
	}
	if value.ServerPicoseconds != nil {
		if err := write(*value.ServerPicoseconds); err != nil {
			return nil, err
		}
	}
	if buf.Len() > maxUADPDynamicPayloadBytes {
		return nil, errors.New("DataValue exceeds 65535 bytes")
	}
	return append([]byte(nil), buf.Bytes()...), nil
}

// DecodeExactDataValuePrefix decodes one exact DataValue prefix.
func DecodeExactDataValuePrefix(wire []byte) (ExactDataValue, int, error) {
	if len(wire) == 0 || wire[0]&0xc0 != 0 {
		return ExactDataValue{}, 0, errors.New("invalid DataValue mask")
	}
	if wire[0]&1 != 0 {
		if len(wire) < 2 || wire[1] == ua.VariantTypeNull || wire[1]&0xc0 != 0 || wire[1] >= ua.VariantTypeDataValue {
			return ExactDataValue{}, 0, errors.New("unsupported inner DataValue Variant type")
		}
		if _, _, err := DecodeExactVariantPrefix(wire[1:]); err != nil {
			return ExactDataValue{}, 0, err
		}
	}
	limit := len(wire)
	if limit > maxUADPDynamicPayloadBytes {
		limit = maxUADPDynamicPayloadBytes
	}
	reader := bytes.NewReader(wire[1:limit])
	dec := ua.NewBinaryDecoder(reader, ua.NewEncodingContext())
	result := ExactDataValue{ValuePresent: wire[0]&1 != 0}
	if result.ValuePresent {
		if err := dec.ReadVariantExact(&result.Value); err != nil {
			return ExactDataValue{}, 0, err
		}
	}
	read := func(size int) ([]byte, error) {
		if reader.Len() < size {
			return nil, errors.New("truncated DataValue")
		}
		part := make([]byte, size)
		if _, err := reader.Read(part); err != nil {
			return nil, err
		}
		return part, nil
	}
	if wire[0]&2 != 0 {
		part, err := read(4)
		if err != nil {
			return ExactDataValue{}, 0, err
		}
		v := binary.LittleEndian.Uint32(part)
		result.StatusCode = &v
	}
	if wire[0]&4 != 0 {
		part, err := read(8)
		if err != nil {
			return ExactDataValue{}, 0, err
		}
		v := int64(binary.LittleEndian.Uint64(part))
		result.SourceTimestamp = &v
	}
	if wire[0]&16 != 0 {
		part, err := read(2)
		if err != nil {
			return ExactDataValue{}, 0, err
		}
		v := binary.LittleEndian.Uint16(part)
		result.SourcePicoseconds = &v
	}
	if wire[0]&8 != 0 {
		part, err := read(8)
		if err != nil {
			return ExactDataValue{}, 0, err
		}
		v := int64(binary.LittleEndian.Uint64(part))
		result.ServerTimestamp = &v
	}
	if wire[0]&32 != 0 {
		part, err := read(2)
		if err != nil {
			return ExactDataValue{}, 0, err
		}
		v := binary.LittleEndian.Uint16(part)
		result.ServerPicoseconds = &v
	}
	return result, limit - reader.Len(), nil
}

// EncodeDataValue encodes one bounded OPC UA DataValue with the library's UA
// Binary encoder.
func EncodeDataValue(value ua.DataValue) ([]byte, error) {
	var buf bytes.Buffer
	enc := ua.NewBinaryEncoder(&buf, ua.NewEncodingContext())
	if err := enc.WriteDataValue(value); err != nil {
		return nil, err
	}
	if buf.Len() > maxUADPDynamicPayloadBytes {
		return nil, errors.New("DataValue exceeds 65535 bytes")
	}
	return append([]byte(nil), buf.Bytes()...), nil
}

// DecodeDataValuePrefix decodes one OPC UA DataValue from the start of wire
// and returns the number of bytes consumed. The caller owns wire and may keep
// subsequent fields after the returned prefix.
func DecodeDataValuePrefix(wire []byte) (ua.DataValue, int, error) {
	if len(wire) == 0 {
		return ua.DataValue{}, 0, errors.New("empty DataValue")
	}
	limit := len(wire)
	if limit > maxUADPDynamicPayloadBytes {
		limit = maxUADPDynamicPayloadBytes
	}
	reader := bytes.NewReader(wire[:limit])
	dec := ua.NewBinaryDecoder(reader, ua.NewEncodingContext())
	var value ua.DataValue
	if err := dec.ReadDataValueExact(&value); err != nil {
		return ua.DataValue{}, 0, err
	}
	return value, limit - reader.Len(), nil
}

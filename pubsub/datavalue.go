package pubsub

import (
	"bytes"
	"errors"

	"github.com/awcullen/opcua/ua"
)

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

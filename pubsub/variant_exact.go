package pubsub

import (
	"bytes"
	"errors"
	"math"
	"unicode/utf8"

	"github.com/awcullen/opcua/ua"
)

// EncodeExactVariant encodes one bounded primitive Variant while preserving
// nullable and raw wire representations. Composite values are owned by
// separate profile codecs.
func EncodeExactVariant(value ua.Variant) ([]byte, error) {
	if err := validateExactVariantPrimitive(value); err != nil {
		return nil, err
	}
	if number, ok := value.(float32); ok && math.IsNaN(float64(number)) {
		return []byte{ua.VariantTypeFloat, 0, 0, 0xc0, 0xff}, nil
	}
	if number, ok := value.(float64); ok && math.IsNaN(number) {
		return []byte{ua.VariantTypeDouble, 0, 0, 0, 0, 0, 0xf8, 0xff}, nil
	}
	var buf bytes.Buffer
	encoder := ua.NewBinaryEncoder(&buf, ua.NewEncodingContext())
	if err := encoder.WriteVariant(value); err != nil {
		return nil, err
	}
	if buf.Len() > maxUADPDynamicPayloadBytes {
		return nil, errors.New("Variant exceeds 65535 bytes")
	}
	return append([]byte(nil), buf.Bytes()...), nil
}

// DecodeExactVariantPrefix decodes one bounded primitive Variant prefix and
// reports the bytes consumed without retaining aliases into wire.
func DecodeExactVariantPrefix(wire []byte) (ua.Variant, int, error) {
	if len(wire) == 0 || len(wire) > maxUADPDynamicPayloadBytes {
		return nil, 0, errors.New("Variant size is invalid")
	}
	kind := wire[0]
	if kind&0xc0 != 0 || !supportedExactVariantPrimitive(kind) {
		return nil, 0, errors.New("unsupported primitive Variant type")
	}
	if kind == ua.VariantTypeBoolean && (len(wire) < 2 || wire[1] > 1) {
		return nil, 0, errors.New("noncanonical Variant Boolean")
	}
	reader := bytes.NewReader(wire)
	decoder := ua.NewBinaryDecoder(reader, ua.NewEncodingContext())
	var value ua.Variant
	if err := decoder.ReadVariantExact(&value); err != nil {
		return nil, 0, err
	}
	if err := validateDecodedExactVariantPrimitive(kind, value); err != nil {
		return nil, 0, err
	}
	return value, len(wire) - reader.Len(), nil
}

func supportedExactVariantPrimitive(kind byte) bool {
	return kind <= ua.VariantTypeXMLElement || kind == ua.VariantTypeStatusCode
}

func validateExactVariantPrimitive(value ua.Variant) error {
	switch value := value.(type) {
	case nil, bool, int8, uint8, int16, uint16, int32, uint32, int64, uint64,
		ua.RawDateTime, ua.RawGUID, ua.StatusCode:
		return nil
	case float32, float64:
		return nil
	case ua.NullableString:
		if value.Null && value.Value != "" || !utf8.ValidString(value.Value) {
			return errors.New("invalid nullable Variant String")
		}
		return nil
	case ua.NullableByteString:
		if value.Null && len(value.Value) != 0 {
			return errors.New("null Variant ByteString carries data")
		}
		return nil
	case ua.NullableXMLElement:
		if value.Null && value.Value != "" || !utf8.ValidString(value.Value) {
			return errors.New("invalid nullable Variant XmlElement")
		}
		return nil
	default:
		return errors.New("unsupported primitive Variant value")
	}
}

func validateDecodedExactVariantPrimitive(kind byte, value ua.Variant) error {
	if err := validateExactVariantPrimitive(value); err != nil {
		return err
	}
	switch kind {
	case ua.VariantTypeString:
		if _, ok := value.(ua.NullableString); !ok {
			return errors.New("invalid Variant String representation")
		}
	case ua.VariantTypeByteString:
		if _, ok := value.(ua.NullableByteString); !ok {
			return errors.New("invalid Variant ByteString representation")
		}
	case ua.VariantTypeXMLElement:
		if _, ok := value.(ua.NullableXMLElement); !ok {
			return errors.New("invalid Variant XmlElement representation")
		}
	}
	return nil
}

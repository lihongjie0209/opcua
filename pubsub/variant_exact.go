package pubsub

import (
	"bytes"
	"encoding/binary"
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
	if kind == ua.VariantTypeLocalizedText {
		if err := validateExactLocalizedTextWire(wire[1:]); err != nil {
			return nil, 0, err
		}
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
	return kind <= ua.VariantTypeXMLElement || kind == ua.VariantTypeNodeID ||
		kind == ua.VariantTypeExpandedNodeID || kind == ua.VariantTypeStatusCode ||
		kind == ua.VariantTypeQualifiedName || kind == ua.VariantTypeLocalizedText ||
		kind == ua.VariantTypeExtensionObject
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
	case ua.RawNodeID:
		return validateExactRawNodeID(value)
	case ua.RawExpandedNodeID:
		if err := validateExactRawNodeID(value.NodeID); err != nil {
			return err
		}
		if value.NamespaceURIPresent && (value.NamespaceURI.Null || value.NamespaceURI.Value == "" ||
			!utf8.ValidString(value.NamespaceURI.Value)) {
			return errors.New("invalid flagged ExpandedNodeId NamespaceUri")
		}
		if value.ServerIndexPresent && value.ServerIndex == 0 {
			return errors.New("invalid flagged ExpandedNodeId ServerIndex")
		}
		return nil
	case ua.RawQualifiedName:
		if value.Name.Null && value.Name.Value != "" || !utf8.ValidString(value.Name.Value) {
			return errors.New("invalid exact QualifiedName")
		}
		return nil
	case ua.LocalizedText:
		if !utf8.ValidString(value.Locale) || !utf8.ValidString(value.Text) {
			return errors.New("invalid exact LocalizedText UTF-8")
		}
		return nil
	case ua.RawExtensionObject:
		if value.RawTypeID == nil {
			return errors.New("exact ExtensionObject requires raw TypeId")
		}
		if err := validateExactRawNodeID(*value.RawTypeID); err != nil {
			return err
		}
		if value.Encoding > 2 || value.Encoding == 0 && len(value.Body) != 0 {
			return errors.New("invalid exact ExtensionObject encoding")
		}
		return nil
	default:
		return errors.New("unsupported exact Variant scalar value")
	}
}

func validateExactLocalizedTextWire(wire []byte) error {
	if len(wire) == 0 || wire[0]&^byte(3) != 0 {
		return errors.New("invalid exact LocalizedText mask")
	}
	offset := 1
	for _, bit := range []byte{1, 2} {
		if wire[0]&bit == 0 {
			continue
		}
		if len(wire)-offset < 4 {
			return errors.New("truncated exact LocalizedText member")
		}
		length := int32(binary.LittleEndian.Uint32(wire[offset:]))
		offset += 4
		if length <= 0 || int(length) > len(wire)-offset {
			return errors.New("invalid exact LocalizedText member length")
		}
		if !utf8.Valid(wire[offset : offset+int(length)]) {
			return errors.New("invalid exact LocalizedText UTF-8")
		}
		offset += int(length)
	}
	return nil
}

func validateExactRawNodeID(value ua.RawNodeID) error {
	switch value.Kind {
	case ua.RawNodeIDNumeric, ua.RawNodeIDGUID:
		return nil
	case ua.RawNodeIDString:
		if value.String.Null && value.String.Value != "" || !utf8.ValidString(value.String.Value) {
			return errors.New("invalid exact String NodeId")
		}
		return nil
	case ua.RawNodeIDOpaque:
		if value.Opaque.Null && len(value.Opaque.Value) != 0 {
			return errors.New("invalid exact Opaque NodeId")
		}
		return nil
	default:
		return errors.New("unsupported exact NodeId kind")
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

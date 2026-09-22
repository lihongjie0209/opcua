package pubsub

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/awcullen/opcua/ua"
)

const (
	variantArrayMask      = byte(0x80)
	variantDimensionsMask = byte(0x40)
	variantTypeMask       = byte(0x3f)
	maxVariantElements    = 1024
	maxVariantDepth       = 10
)

// ExactVariantValue preserves one supported scalar, array or matrix Variant.
// Value carries an exact UA scalar. DataValue and DiagnosticInfo carry the two
// scalar forms that require profile-specific exact wrappers.
type ExactVariantValue struct {
	Type           byte
	Value          ua.Variant
	DataValue      *ExactDataValue
	DiagnosticInfo *ua.DiagnosticInfo
	Null           bool
	Elements       []ExactVariantValue
	Dimensions     []int32
}

// EncodeExactVariantValue encodes one bounded exact Variant value.
func EncodeExactVariantValue(value ExactVariantValue) ([]byte, error) {
	return encodeExactVariantValue(value, 0)
}

func encodeExactVariantValue(value ExactVariantValue, depth int) ([]byte, error) {
	if value.Type&variantArrayMask == 0 {
		return encodeExactVariantScalarValue(value)
	}
	base := value.Type & variantTypeMask
	if base == ua.VariantTypeNull || base > 31 || base == ua.VariantTypeVariant && depth >= maxVariantDepth {
		return nil, errors.New("unsupported exact Variant array type or nesting")
	}
	if base >= 26 {
		return nil, errors.New("reserved Variant arrays are decode-only")
	}
	if value.Value != nil || value.DataValue != nil || value.DiagnosticInfo != nil {
		return nil, errors.New("exact Variant array carries scalar value")
	}
	if len(value.Elements) > maxVariantElements {
		return nil, errors.New("exact Variant array exceeds 1024 elements")
	}
	matrix := value.Type&variantDimensionsMask != 0
	if value.Null {
		if matrix || len(value.Elements) != 0 || value.Elements != nil || len(value.Dimensions) != 0 {
			return nil, errors.New("invalid null exact Variant collection")
		}
		return []byte{value.Type, 0xff, 0xff, 0xff, 0xff}, nil
	}
	if value.Elements == nil {
		return nil, errors.New("non-null exact Variant array requires elements")
	}
	if err := validateExactVariantDimensions(matrix, value.Dimensions, len(value.Elements)); err != nil {
		return nil, err
	}
	wire := []byte{value.Type, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(wire[1:], uint32(len(value.Elements)))
	for index, element := range value.Elements {
		var encoded []byte
		var err error
		if base == ua.VariantTypeVariant {
			encoded, err = encodeExactVariantValue(element, depth+1)
		} else {
			if element.Type != base {
				return nil, fmt.Errorf("exact Variant element %d type mismatch", index)
			}
			encoded, err = encodeExactVariantScalarValue(element)
			if err == nil {
				encoded = encoded[1:]
			}
		}
		if err != nil {
			return nil, fmt.Errorf("exact Variant element %d: %w", index, err)
		}
		if len(wire) > maxUADPDynamicPayloadBytes-len(encoded) {
			return nil, errors.New("exact Variant collection exceeds 65535 bytes")
		}
		wire = append(wire, encoded...)
	}
	if matrix {
		if len(wire) > maxUADPDynamicPayloadBytes-4-4*len(value.Dimensions) {
			return nil, errors.New("exact Variant dimensions exceed 65535 bytes")
		}
		wire = binary.LittleEndian.AppendUint32(wire, uint32(len(value.Dimensions)))
		for _, dimension := range value.Dimensions {
			wire = binary.LittleEndian.AppendUint32(wire, uint32(dimension))
		}
	}
	return wire, nil
}

func encodeExactVariantScalarValue(value ExactVariantValue) ([]byte, error) {
	if value.Type&0xc0 != 0 || value.Null || value.Elements != nil || len(value.Dimensions) != 0 {
		return nil, errors.New("invalid exact Variant scalar model")
	}
	switch value.Type {
	case ua.VariantTypeDataValue:
		if value.DataValue == nil || value.Value != nil || value.DiagnosticInfo != nil {
			return nil, errors.New("invalid exact DataValue Variant")
		}
		body, err := EncodeExactDataValue(*value.DataValue)
		return append([]byte{value.Type}, body...), err
	case ua.VariantTypeDiagnosticInfo:
		if value.DiagnosticInfo == nil || value.Value != nil || value.DataValue != nil {
			return nil, errors.New("invalid exact DiagnosticInfo Variant")
		}
		body, err := EncodeExactDiagnosticInfo(*value.DiagnosticInfo)
		return append([]byte{value.Type}, body...), err
	case ua.VariantTypeVariant, 26, 27, 28, 29, 30, 31:
		return nil, errors.New("unsupported exact Variant scalar type")
	default:
		if value.DataValue != nil || value.DiagnosticInfo != nil {
			return nil, errors.New("exact Variant scalar carries wrong value model")
		}
		wire, err := EncodeExactVariant(value.Value)
		if err != nil || len(wire) == 0 || wire[0] != value.Type {
			return nil, errors.New("exact Variant scalar type mismatch")
		}
		return wire, nil
	}
}

// DecodeExactVariantValuePrefix decodes one exact Variant value prefix.
func DecodeExactVariantValuePrefix(wire []byte) (ExactVariantValue, int, error) {
	return decodeExactVariantValuePrefix(wire, 0)
}

func decodeExactVariantValuePrefix(wire []byte, depth int) (ExactVariantValue, int, error) {
	if len(wire) == 0 || len(wire) > maxUADPDynamicPayloadBytes {
		return ExactVariantValue{}, 0, errors.New("exact Variant size is invalid")
	}
	kind := wire[0]
	if kind&variantArrayMask == 0 {
		return decodeExactVariantScalarValue(wire)
	}
	base := kind & variantTypeMask
	if base == ua.VariantTypeNull || base > 31 || base == ua.VariantTypeVariant && depth >= maxVariantDepth || len(wire) < 5 {
		return ExactVariantValue{}, 0, errors.New("invalid exact Variant collection")
	}
	count := int32(binary.LittleEndian.Uint32(wire[1:]))
	if count < -1 || count > maxVariantElements {
		return ExactVariantValue{}, 0, errors.New("invalid exact Variant array length")
	}
	value := ExactVariantValue{Type: kind}
	matrix := kind&variantDimensionsMask != 0
	if count == -1 {
		if matrix {
			return ExactVariantValue{}, 0, errors.New("matrix cannot be null")
		}
		value.Null = true
		return value, 5, nil
	}
	if matrix && count == 0 {
		return ExactVariantValue{}, 0, errors.New("matrix cannot be empty")
	}
	value.Elements = make([]ExactVariantValue, 0, count)
	offset := 5
	for index := range int(count) {
		var element ExactVariantValue
		var used int
		var err error
		if base == ua.VariantTypeVariant {
			element, used, err = decodeExactVariantValuePrefix(wire[offset:], depth+1)
		} else {
			prefixed := make([]byte, 1, 1+len(wire)-offset)
			prefixed[0] = base
			prefixed = append(prefixed, wire[offset:]...)
			element, used, err = decodeExactVariantScalarValue(prefixed)
			used--
		}
		if err != nil || used < 0 || used > len(wire)-offset {
			return ExactVariantValue{}, 0, fmt.Errorf("invalid exact Variant element %d", index)
		}
		value.Elements = append(value.Elements, element)
		offset += used
	}
	if matrix {
		if len(wire)-offset < 4 {
			return ExactVariantValue{}, 0, errors.New("truncated exact Variant rank")
		}
		rank := int32(binary.LittleEndian.Uint32(wire[offset:]))
		offset += 4
		if rank < 2 || rank > maxVariantElements || len(wire)-offset < int(rank)*4 {
			return ExactVariantValue{}, 0, errors.New("invalid exact Variant dimensions")
		}
		value.Dimensions = make([]int32, rank)
		for i := range value.Dimensions {
			value.Dimensions[i] = int32(binary.LittleEndian.Uint32(wire[offset:]))
			offset += 4
		}
		if err := validateExactVariantDimensions(true, value.Dimensions, len(value.Elements)); err != nil {
			return ExactVariantValue{}, 0, err
		}
	}
	return value, offset, nil
}

func decodeExactVariantScalarValue(wire []byte) (ExactVariantValue, int, error) {
	if len(wire) == 0 {
		return ExactVariantValue{}, 0, errors.New("empty exact Variant")
	}
	kind := wire[0]
	switch kind {
	case ua.VariantTypeDataValue:
		value, used, err := DecodeExactDataValuePrefix(wire[1:])
		if err != nil {
			return ExactVariantValue{}, 0, err
		}
		return ExactVariantValue{Type: kind, DataValue: &value}, used + 1, nil
	case ua.VariantTypeDiagnosticInfo:
		value, used, err := DecodeExactDiagnosticInfoPrefix(wire[1:])
		if err != nil {
			return ExactVariantValue{}, 0, err
		}
		return ExactVariantValue{Type: kind, DiagnosticInfo: &value}, used + 1, nil
	case ua.VariantTypeVariant:
		return ExactVariantValue{}, 0, errors.New("unsupported exact Variant scalar type")
	case 26, 27, 28, 29, 30, 31:
		if len(wire) < 5 {
			return ExactVariantValue{}, 0, errors.New("truncated reserved Variant scalar")
		}
		length := int32(binary.LittleEndian.Uint32(wire[1:]))
		if length < -1 || length > maxUADPDynamicPayloadBytes || length >= 0 && int(length) > len(wire)-5 {
			return ExactVariantValue{}, 0, errors.New("invalid reserved Variant scalar length")
		}
		value := ua.NullableByteString{Null: length == -1}
		used := 5
		if length >= 0 {
			value.Value = append([]byte{}, wire[5:5+int(length)]...)
			used += int(length)
		}
		return ExactVariantValue{Type: kind, Value: value}, used, nil
	default:
		value, used, err := DecodeExactVariantPrefix(wire)
		if err != nil {
			return ExactVariantValue{}, 0, err
		}
		return ExactVariantValue{Type: kind, Value: value}, used, nil
	}
}

func validateExactVariantDimensions(matrix bool, dimensions []int32, count int) error {
	if !matrix {
		if len(dimensions) != 0 {
			return errors.New("array carries matrix dimensions")
		}
		return nil
	}
	if len(dimensions) < 2 || len(dimensions) > maxVariantElements {
		return errors.New("matrix rank is invalid")
	}
	product := 1
	for _, dimension := range dimensions {
		if dimension <= 0 || int(dimension) > maxVariantElements || product > maxVariantElements/int(dimension) {
			return errors.New("matrix dimension is invalid")
		}
		product *= int(dimension)
	}
	if product != count {
		return errors.New("matrix dimensions mismatch element count")
	}
	return nil
}

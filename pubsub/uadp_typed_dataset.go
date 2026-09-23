package pubsub

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ExactVariantField is one typed DataSetMessage field and metadata index.
type ExactVariantField struct {
	Index uint16
	Value ExactVariantValue
}

// TypedUADPDataSet is one bounded Variant DataSetMessage.
type TypedUADPDataSet struct {
	Header    UADPDataSetHeader
	Heartbeat bool
	Fields    []ExactVariantField
}

// EncodeTypedUADPDataSet encodes one complete typed DataSetMessage.
func EncodeTypedUADPDataSet(frame TypedUADPDataSet, expectedFields int) ([]byte, error) {
	if expectedFields < 0 || expectedFields > maxVariantElements {
		return nil, errors.New("typed UADP metadata field count is invalid")
	}
	if err := validateTypedUADPBody(frame, expectedFields); err != nil {
		return nil, err
	}
	wire, err := EncodeUADPDataSetHeader(frame.Header)
	if err != nil {
		return nil, err
	}
	if frame.Header.Type == UADPDataSetKeepAlive || frame.Heartbeat {
		return wire, nil
	}
	wire = binary.LittleEndian.AppendUint16(wire, uint16(len(frame.Fields)))
	seen := make([]bool, expectedFields)
	for index, field := range frame.Fields {
		ordered := frame.Header.Type == UADPDataSetKeyFrame || frame.Header.Type == UADPDataSetEvent ||
			frame.Header.Type == UADPDataSetActionRequest || frame.Header.Type == UADPDataSetActionResponse
		if ordered && int(field.Index) != index {
			return nil, fmt.Errorf("typed UADP ordered field %d index mismatch", index)
		}
		if frame.Header.Type == UADPDataSetDeltaFrame {
			if int(field.Index) >= expectedFields || seen[field.Index] {
				return nil, fmt.Errorf("typed UADP DeltaFrame field %d index invalid or duplicate", index)
			}
			seen[field.Index] = true
			wire = binary.LittleEndian.AppendUint16(wire, field.Index)
		}
		encoded, err := EncodeExactVariantValue(field.Value)
		if err != nil {
			return nil, fmt.Errorf("typed UADP field %d: %w", index, err)
		}
		if len(wire) > maxUADPDynamicPayloadBytes-len(encoded) {
			return nil, errors.New("typed UADP DataSetMessage exceeds 65535 bytes")
		}
		wire = append(wire, encoded...)
	}
	return wire, nil
}

// DecodeTypedUADPDataSet decodes one complete typed DataSetMessage.
func DecodeTypedUADPDataSet(wire []byte, expectedFields int) (TypedUADPDataSet, error) {
	if expectedFields < 0 || expectedFields > maxVariantElements || len(wire) == 0 || len(wire) > maxUADPDynamicPayloadBytes {
		return TypedUADPDataSet{}, errors.New("typed UADP DataSetMessage size or metadata count is invalid")
	}
	header, offset, err := DecodeUADPDataSetHeader(wire)
	if err != nil {
		return TypedUADPDataSet{}, err
	}
	frame := TypedUADPDataSet{Header: header}
	if expectedFields == 0 && header.Type != UADPDataSetActionRequest && header.Type != UADPDataSetActionResponse {
		return TypedUADPDataSet{}, errors.New("zero metadata fields require an Action DataSetMessage")
	}
	if header.Type == UADPDataSetKeepAlive {
		if offset != len(wire) {
			return TypedUADPDataSet{}, errors.New("UADP KeepAlive has trailing body")
		}
		return frame, nil
	}
	if header.Type == UADPDataSetKeyFrame && offset == len(wire) {
		frame.Heartbeat = true
		return frame, nil
	}
	if len(wire)-offset < 2 {
		return TypedUADPDataSet{}, errors.New("truncated typed UADP FieldCount")
	}
	count := int(binary.LittleEndian.Uint16(wire[offset:]))
	offset += 2
	if err := validateTypedUADPCount(header.Type, count, expectedFields); err != nil {
		return TypedUADPDataSet{}, err
	}
	frame.Fields = make([]ExactVariantField, 0, count)
	seen := make([]bool, expectedFields)
	for index := 0; index < count; index++ {
		fieldIndex := uint16(index)
		if header.Type == UADPDataSetDeltaFrame {
			if len(wire)-offset < 2 {
				return TypedUADPDataSet{}, errors.New("truncated typed UADP DeltaFrame index")
			}
			fieldIndex = binary.LittleEndian.Uint16(wire[offset:])
			offset += 2
			if int(fieldIndex) >= expectedFields || seen[fieldIndex] {
				return TypedUADPDataSet{}, fmt.Errorf("typed UADP DeltaFrame field %d index invalid or duplicate", index)
			}
			seen[fieldIndex] = true
		}
		value, used, err := DecodeExactVariantValuePrefix(wire[offset:])
		if err != nil {
			return TypedUADPDataSet{}, fmt.Errorf("typed UADP field %d: %w", index, err)
		}
		offset += used
		frame.Fields = append(frame.Fields, ExactVariantField{Index: fieldIndex, Value: value})
	}
	if offset != len(wire) {
		return TypedUADPDataSet{}, errors.New("typed UADP DataSetMessage has trailing bytes")
	}
	return frame, nil
}

func validateTypedUADPBody(frame TypedUADPDataSet, expectedFields int) error {
	switch frame.Header.Type {
	case UADPDataSetKeyFrame:
		if frame.Heartbeat {
			if len(frame.Fields) != 0 {
				return errors.New("typed UADP heartbeat cannot carry fields")
			}
		} else if len(frame.Fields) != expectedFields {
			return errors.New("typed UADP KeyFrame field count mismatch")
		}
	case UADPDataSetDeltaFrame:
		if frame.Heartbeat || len(frame.Fields) > expectedFields {
			return errors.New("typed UADP DeltaFrame fields invalid")
		}
	case UADPDataSetEvent:
		if frame.Heartbeat || len(frame.Fields) != expectedFields {
			return errors.New("typed UADP Event field count mismatch")
		}
	case UADPDataSetActionRequest, UADPDataSetActionResponse:
		if frame.Heartbeat || len(frame.Fields) != expectedFields {
			return errors.New("typed UADP Action field count mismatch")
		}
	case UADPDataSetKeepAlive:
		if frame.Heartbeat || len(frame.Fields) != 0 {
			return errors.New("typed UADP KeepAlive cannot carry fields")
		}
	default:
		return errors.New("unsupported typed UADP DataSetMessage type")
	}
	if expectedFields == 0 && frame.Header.Type != UADPDataSetActionRequest && frame.Header.Type != UADPDataSetActionResponse {
		return errors.New("zero metadata fields require an Action DataSetMessage")
	}
	return nil
}

func validateTypedUADPCount(kind UADPDataSetMessageType, count, expected int) error {
	switch kind {
	case UADPDataSetKeyFrame, UADPDataSetEvent, UADPDataSetActionRequest, UADPDataSetActionResponse:
		if count != expected {
			return errors.New("typed UADP field count mismatches metadata")
		}
	case UADPDataSetDeltaFrame:
		if count > expected {
			return errors.New("typed UADP DeltaFrame field count exceeds metadata")
		}
	default:
		return errors.New("unsupported typed UADP DataSetMessage type")
	}
	return nil
}

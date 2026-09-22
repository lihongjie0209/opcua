package pubsub

import (
	"bytes"
	"fmt"

	"github.com/awcullen/opcua/ua"
)

// RawFieldWidth validates metadata and returns its fixed RawData wire width.
func RawFieldWidth(meta RawFieldMeta) (int, error) {
	if meta.Type == RawStructureType {
		return rawStructureFieldWidth(meta, 0)
	}
	if meta.Structure != nil {
		return 0, fmt.Errorf("unexpected RawData Structure metadata")
	}
	if meta.Type == RawOptionSetType {
		if meta.ValueRank != 0 && meta.ValueRank != -1 || len(meta.ArrayDimensions) != 0 || meta.MaxStringLength != 0 {
			return 0, fmt.Errorf("RawData OptionSet must be scalar")
		}
		return rawOptionSetWidth(meta.OptionSetLength)
	}
	if meta.OptionSetLength != 0 {
		return 0, fmt.Errorf("unexpected RawData OptionSet length")
	}
	if meta.ValueRank > 1 {
		width, maximum, err := rawMatrixLayout(meta.Type, meta.ValueRank, meta.ArrayDimensions, meta.MaxStringLength)
		if err != nil {
			return 0, err
		}
		return 4 + 4*int(meta.ValueRank) + maximum*width, nil
	}
	if meta.ValueRank == 1 {
		width, maximum, err := rawArrayLayout(meta.Type, meta.ValueRank, meta.ArrayDimensions, meta.MaxStringLength)
		if err != nil {
			return 0, err
		}
		return 4 + maximum*width, nil
	}
	if meta.ValueRank != 0 && meta.ValueRank != -1 || len(meta.ArrayDimensions) != 0 {
		return 0, fmt.Errorf("unsupported RawData ValueRank")
	}
	if meta.Type == RawString || meta.Type == RawByteString {
		if meta.MaxStringLength == 0 || meta.MaxStringLength > maxRawMessageBytes-4 {
			return 0, fmt.Errorf("invalid RawData string length")
		}
		return 4 + int(meta.MaxStringLength), nil
	}
	if meta.MaxStringLength != 0 {
		return 0, fmt.Errorf("unexpected RawData string length")
	}
	width := rawFixedWidth(meta.Type)
	if width == 0 {
		return 0, fmt.Errorf("unsupported RawData type")
	}
	return width, nil
}

func rawStructureWidth(meta *RawStructureMeta, depth int) (int, error) {
	if meta == nil || depth > 16 || len(meta.Fields) == 0 || len(meta.Fields) > 256 {
		return 0, fmt.Errorf("invalid RawData Structure definition")
	}
	names := make(map[string]struct{}, len(meta.Fields))
	total := 0
	for index, named := range meta.Fields {
		if named.Name == "" {
			return 0, fmt.Errorf("RawData Structure field %d has empty name", index)
		}
		if _, exists := names[named.Name]; exists {
			return 0, fmt.Errorf("duplicate RawData Structure field %q", named.Name)
		}
		names[named.Name] = struct{}{}
		width, err := rawStructureFieldWidth(named.Field, depth)
		if err != nil {
			return 0, fmt.Errorf("RawData Structure field %q: %w", named.Name, err)
		}
		if total > maxRawMessageBytes-width {
			return 0, fmt.Errorf("RawData Structure exceeds size limit")
		}
		total += width
	}
	return total, nil
}

func rawStructureFieldWidth(meta RawFieldMeta, depth int) (int, error) {
	if meta.ValueRank != 0 && meta.ValueRank != -1 || len(meta.ArrayDimensions) != 0 {
		return 0, fmt.Errorf("Structure arrays are not supported")
	}
	switch meta.Type {
	case RawStructureType:
		if meta.MaxStringLength != 0 || meta.OptionSetLength != 0 {
			return 0, fmt.Errorf("invalid nested Structure metadata")
		}
		return rawStructureWidth(meta.Structure, depth+1)
	case RawOptionSetType:
		if meta.Structure != nil || meta.MaxStringLength != 0 {
			return 0, fmt.Errorf("invalid OptionSet metadata")
		}
		return rawOptionSetWidth(meta.OptionSetLength)
	case RawString, RawByteString:
		if meta.Structure != nil || meta.OptionSetLength != 0 || meta.MaxStringLength == 0 || meta.MaxStringLength > maxRawMessageBytes-4 {
			return 0, fmt.Errorf("invalid string metadata")
		}
		return 4 + int(meta.MaxStringLength), nil
	default:
		if meta.Structure != nil || meta.OptionSetLength != 0 || meta.MaxStringLength != 0 {
			return 0, fmt.Errorf("unexpected field metadata")
		}
		width := rawFixedWidth(meta.Type)
		if width == 0 {
			return 0, fmt.Errorf("unsupported Structure field type")
		}
		return width, nil
	}
}

func encodeRawStructure(buf *bytes.Buffer, enc *ua.BinaryEncoder, field RawField, depth int) error {
	width, err := rawStructureWidth(field.Structure, depth)
	if err != nil {
		return err
	}
	if field.ValueRank != 0 && field.ValueRank != -1 || len(field.ArrayDimensions) != 0 || field.MaxStringLength != 0 || field.OptionSetLength != 0 {
		return fmt.Errorf("RawData Structure must be scalar")
	}
	value, ok := field.Value.(RawStructure)
	if !ok || len(value.Fields) != len(field.Structure.Fields) {
		return fmt.Errorf("RawData Structure value fields mismatch")
	}
	if buf.Len()+width > maxRawMessageBytes {
		return fmt.Errorf("RawData Structure exceeds message size limit")
	}
	for _, named := range field.Structure.Fields {
		member, exists := value.Fields[named.Name]
		if !exists {
			return fmt.Errorf("RawData Structure field %q is missing", named.Name)
		}
		if err := encodeRawStructureField(buf, enc, named.Field, member, depth); err != nil {
			return fmt.Errorf("RawData Structure field %q: %w", named.Name, err)
		}
	}
	return nil
}

func encodeRawStructureField(buf *bytes.Buffer, enc *ua.BinaryEncoder, meta RawFieldMeta, value any, depth int) error {
	field := RawField{Type: meta.Type, Value: value, MaxStringLength: meta.MaxStringLength, ValueRank: meta.ValueRank, ArrayDimensions: meta.ArrayDimensions, OptionSetLength: meta.OptionSetLength, Structure: meta.Structure}
	switch meta.Type {
	case RawStructureType:
		return encodeRawStructure(buf, enc, field, depth+1)
	case RawOptionSetType:
		return encodeRawOptionSet(buf, enc, field)
	case RawString, RawByteString:
		if err := writeRawMatrixElement(buf, enc, field, value); err != nil {
			return err
		}
		return nil
	default:
		return writeRawField(enc, field)
	}
}

func decodeRawStructure(dec *ua.BinaryDecoder, reader *bytes.Reader, meta RawFieldMeta, depth int) (RawStructure, error) {
	width, err := rawStructureWidth(meta.Structure, depth)
	if err != nil {
		return RawStructure{}, err
	}
	if meta.ValueRank != 0 && meta.ValueRank != -1 || len(meta.ArrayDimensions) != 0 || meta.MaxStringLength != 0 || meta.OptionSetLength != 0 {
		return RawStructure{}, fmt.Errorf("RawData Structure must be scalar")
	}
	if reader.Len() < width {
		return RawStructure{}, fmt.Errorf("truncated RawData Structure")
	}
	value := RawStructure{Fields: make(map[string]any, len(meta.Structure.Fields))}
	for _, named := range meta.Structure.Fields {
		member, err := decodeRawStructureField(dec, reader, named.Field, depth)
		if err != nil {
			return RawStructure{}, fmt.Errorf("RawData Structure field %q: %w", named.Name, err)
		}
		value.Fields[named.Name] = member
	}
	return value, nil
}

func decodeRawStructureField(dec *ua.BinaryDecoder, reader *bytes.Reader, meta RawFieldMeta, depth int) (any, error) {
	switch meta.Type {
	case RawStructureType:
		return decodeRawStructure(dec, reader, meta, depth+1)
	case RawOptionSetType:
		return decodeRawOptionSet(dec, reader, meta)
	case RawString, RawByteString:
		return readPaddedStringArrayElement(dec, reader, meta)
	default:
		return readRawField(dec, meta.Type)
	}
}

package pubsub

import (
	"bytes"
	"fmt"
	"io"

	"github.com/awcullen/opcua/ua"
)

// RawFieldWidth validates metadata and returns its fixed RawData wire width.
func RawFieldWidth(meta RawFieldMeta) (int, error) {
	if meta.Type == RawUnionType {
		return rawUnionFieldWidth(meta, 1)
	}
	if meta.Union != nil {
		return 0, fmt.Errorf("unexpected RawData Union metadata")
	}
	if meta.Type == RawStructureType {
		return rawStructureFieldWidth(meta, 0)
	}
	if meta.Structure != nil {
		return 0, fmt.Errorf("unexpected RawData Structure metadata")
	}
	if meta.Type == RawOptionSetType {
		if meta.ValueRank > 0 {
			width, maximum, err := rawOptionSetCollectionLayout(meta)
			if err != nil {
				return 0, err
			}
			if meta.ValueRank == 1 {
				return 4 + maximum*width, nil
			}
			return 4 + 4*int(meta.ValueRank) + maximum*width, nil
		}
		if meta.ValueRank != 0 && meta.ValueRank != -1 || len(meta.ArrayDimensions) != 0 || meta.MaxStringLength != 0 {
			return 0, fmt.Errorf("invalid RawData OptionSet rank")
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
	optionalCount := 0
	for index, named := range meta.Fields {
		if named.Name == "" {
			return 0, fmt.Errorf("RawData Structure field %d has empty name", index)
		}
		if _, exists := names[named.Name]; exists {
			return 0, fmt.Errorf("duplicate RawData Structure field %q", named.Name)
		}
		names[named.Name] = struct{}{}
		if named.Optional {
			optionalCount++
			if optionalCount > 32 {
				return 0, fmt.Errorf("RawData Structure has more than 32 optional fields")
			}
		}
		width, err := rawStructureFieldWidth(named.Field, depth)
		if err != nil {
			return 0, fmt.Errorf("RawData Structure field %q: %w", named.Name, err)
		}
		if total > maxRawMessageBytes-width {
			return 0, fmt.Errorf("RawData Structure exceeds size limit")
		}
		total += width
	}
	if optionalCount != 0 {
		if total > maxRawMessageBytes-4 {
			return 0, fmt.Errorf("RawData Structure exceeds size limit")
		}
		total += 4
	}
	return total, nil
}

func rawStructureFieldWidth(meta RawFieldMeta, depth int) (int, error) {
	if meta.ValueRank > 0 {
		if meta.Type == RawStructureType {
			width, maximum, err := rawStructureCollectionLayout(meta, depth+1)
			if err != nil {
				return 0, err
			}
			if meta.ValueRank == 1 {
				return 4 + maximum*width, nil
			}
			return 4 + 4*int(meta.ValueRank) + maximum*width, nil
		}
		if meta.Type == RawOptionSetType {
			width, maximum, err := rawOptionSetCollectionLayout(meta)
			if err != nil {
				return 0, err
			}
			if meta.ValueRank == 1 {
				return 4 + maximum*width, nil
			}
			return 4 + 4*int(meta.ValueRank) + maximum*width, nil
		}
		if meta.Type == RawStructureType || meta.Type == RawUnionType || meta.Structure != nil || meta.Union != nil || meta.OptionSetLength != 0 {
			return 0, fmt.Errorf("unsupported Structure array element type")
		}
		if meta.ValueRank == 1 {
			width, maximum, err := rawArrayLayout(meta.Type, meta.ValueRank, meta.ArrayDimensions, meta.MaxStringLength)
			if err != nil {
				return 0, err
			}
			return 4 + maximum*width, nil
		}
		width, maximum, err := rawMatrixLayout(meta.Type, meta.ValueRank, meta.ArrayDimensions, meta.MaxStringLength)
		if err != nil {
			return 0, err
		}
		return 4 + 4*int(meta.ValueRank) + maximum*width, nil
	}
	if meta.ValueRank != 0 && meta.ValueRank != -1 || len(meta.ArrayDimensions) != 0 {
		return 0, fmt.Errorf("invalid Structure field rank")
	}
	switch meta.Type {
	case RawUnionType:
		if meta.Structure != nil || meta.MaxStringLength != 0 || meta.OptionSetLength != 0 {
			return 0, fmt.Errorf("invalid nested Union metadata")
		}
		return rawUnionWidth(meta.Union, depth+1)
	case RawStructureType:
		if meta.Union != nil || meta.MaxStringLength != 0 || meta.OptionSetLength != 0 {
			return 0, fmt.Errorf("invalid nested Structure metadata")
		}
		return rawStructureWidth(meta.Structure, depth+1)
	case RawOptionSetType:
		if meta.Structure != nil || meta.Union != nil || meta.MaxStringLength != 0 {
			return 0, fmt.Errorf("invalid OptionSet metadata")
		}
		return rawOptionSetWidth(meta.OptionSetLength)
	case RawString, RawByteString:
		if meta.Structure != nil || meta.Union != nil || meta.OptionSetLength != 0 || meta.MaxStringLength == 0 || meta.MaxStringLength > maxRawMessageBytes-4 {
			return 0, fmt.Errorf("invalid string metadata")
		}
		return 4 + int(meta.MaxStringLength), nil
	default:
		if meta.Structure != nil || meta.Union != nil || meta.OptionSetLength != 0 || meta.MaxStringLength != 0 {
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
	if !ok || len(value.Fields) > len(field.Structure.Fields) {
		return fmt.Errorf("RawData Structure value fields mismatch")
	}
	if buf.Len()+width > maxRawMessageBytes {
		return fmt.Errorf("RawData Structure exceeds message size limit")
	}
	known := make(map[string]struct{}, len(field.Structure.Fields))
	var mask uint32
	optionalIndex := uint(0)
	for _, named := range field.Structure.Fields {
		known[named.Name] = struct{}{}
		_, exists := value.Fields[named.Name]
		if named.Optional {
			if exists {
				mask |= uint32(1) << optionalIndex
			}
			optionalIndex++
		} else if !exists {
			return fmt.Errorf("RawData Structure field %q is missing", named.Name)
		}
	}
	for name := range value.Fields {
		if _, exists := known[name]; !exists {
			return fmt.Errorf("unknown RawData Structure field %q", name)
		}
	}
	if optionalIndex != 0 {
		if err := enc.WriteUInt32(mask); err != nil {
			return err
		}
	}
	for _, named := range field.Structure.Fields {
		member, exists := value.Fields[named.Name]
		if !exists {
			width, err := rawStructureFieldWidth(named.Field, depth)
			if err != nil {
				return err
			}
			buf.Write(make([]byte, width))
			continue
		}
		if err := encodeRawStructureField(buf, enc, named.Field, member, depth); err != nil {
			return fmt.Errorf("RawData Structure field %q: %w", named.Name, err)
		}
	}
	return nil
}

func encodeRawStructureField(buf *bytes.Buffer, enc *ua.BinaryEncoder, meta RawFieldMeta, value any, depth int) error {
	field := RawField{Type: meta.Type, Value: value, MaxStringLength: meta.MaxStringLength, ValueRank: meta.ValueRank, ArrayDimensions: meta.ArrayDimensions, OptionSetLength: meta.OptionSetLength, Structure: meta.Structure, Union: meta.Union}
	if meta.Type == RawStructureType && meta.ValueRank > 0 {
		if meta.ValueRank > 1 {
			return encodeRawStructureMatrix(buf, enc, field, depth+1)
		}
		return encodeRawStructureArray(buf, enc, field, depth+1)
	}
	if meta.Type == RawOptionSetType {
		if meta.ValueRank > 1 {
			return encodeRawOptionSetMatrix(buf, enc, field)
		}
		if meta.ValueRank == 1 {
			return encodeRawOptionSetArray(buf, enc, field)
		}
		return encodeRawOptionSet(buf, enc, field)
	}
	if meta.ValueRank > 1 {
		return encodeRawMatrix(buf, enc, field)
	}
	if meta.ValueRank == 1 {
		return encodeRawArray(buf, enc, field)
	}
	switch meta.Type {
	case RawUnionType:
		return encodeRawUnion(buf, enc, field, depth+1)
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
	optionalCount := uint(0)
	for _, named := range meta.Structure.Fields {
		if named.Optional {
			optionalCount++
		}
	}
	var mask uint32
	if optionalCount != 0 {
		if err := dec.ReadUInt32(&mask); err != nil {
			return RawStructure{}, err
		}
		valid := ^uint32(0)
		if optionalCount < 32 {
			valid = uint32(1)<<optionalCount - 1
		}
		if mask&^valid != 0 {
			return RawStructure{}, fmt.Errorf("RawData Structure has unassigned EncodingMask bits")
		}
	}
	optionalIndex := uint(0)
	for _, named := range meta.Structure.Fields {
		present := true
		if named.Optional {
			present = mask&(uint32(1)<<optionalIndex) != 0
			optionalIndex++
		}
		if !present {
			width, err := rawStructureFieldWidth(named.Field, depth)
			if err != nil {
				return RawStructure{}, err
			}
			padding := make([]byte, width)
			if _, err := io.ReadFull(reader, padding); err != nil {
				return RawStructure{}, err
			}
			for _, b := range padding {
				if b != 0 {
					return RawStructure{}, fmt.Errorf("nonzero optional RawData Structure padding")
				}
			}
			continue
		}
		member, err := decodeRawStructureField(dec, reader, named.Field, depth)
		if err != nil {
			return RawStructure{}, fmt.Errorf("RawData Structure field %q: %w", named.Name, err)
		}
		value.Fields[named.Name] = member
	}
	return value, nil
}

func decodeRawStructureField(dec *ua.BinaryDecoder, reader *bytes.Reader, meta RawFieldMeta, depth int) (any, error) {
	if meta.Type == RawStructureType && meta.ValueRank > 0 {
		if meta.ValueRank > 1 {
			return decodeRawStructureMatrix(dec, reader, meta, depth+1)
		}
		return decodeRawStructureArray(dec, reader, meta, depth+1)
	}
	if meta.Type == RawOptionSetType {
		if meta.ValueRank > 1 {
			return decodeRawOptionSetMatrix(dec, reader, meta)
		}
		if meta.ValueRank == 1 {
			return decodeRawOptionSetArray(dec, reader, meta)
		}
		return decodeRawOptionSet(dec, reader, meta)
	}
	if meta.ValueRank > 1 {
		return decodeRawMatrix(dec, reader, meta)
	}
	if meta.ValueRank == 1 {
		return decodeRawArray(dec, reader, meta)
	}
	switch meta.Type {
	case RawUnionType:
		return decodeRawUnion(dec, reader, meta, depth+1)
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

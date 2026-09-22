package pubsub

import (
	"bytes"
	"fmt"
	"io"

	"github.com/awcullen/opcua/ua"
)

func rawUnionWidth(meta *RawUnionMeta, depth int) (int, error) {
	if meta == nil || depth > 16 || len(meta.Fields) == 0 || len(meta.Fields) > 256 {
		return 0, fmt.Errorf("invalid RawData Union definition")
	}
	names := make(map[string]struct{}, len(meta.Fields))
	maximum := 0
	for index, named := range meta.Fields {
		if named.Name == "" {
			return 0, fmt.Errorf("RawData Union field %d has empty name", index)
		}
		if _, exists := names[named.Name]; exists {
			return 0, fmt.Errorf("duplicate RawData Union field %q", named.Name)
		}
		names[named.Name] = struct{}{}
		width, err := rawStructureFieldWidth(named.Field, depth)
		if err != nil {
			return 0, fmt.Errorf("RawData Union field %q: %w", named.Name, err)
		}
		if width > maximum {
			maximum = width
		}
	}
	if maximum > maxRawMessageBytes-4 {
		return 0, fmt.Errorf("RawData Union exceeds size limit")
	}
	return 4 + maximum, nil
}

func rawUnionFieldWidth(meta RawFieldMeta, depth int) (int, error) {
	if meta.ValueRank != 0 && meta.ValueRank != -1 || len(meta.ArrayDimensions) != 0 || meta.MaxStringLength != 0 || meta.OptionSetLength != 0 || meta.Structure != nil {
		return 0, fmt.Errorf("RawData Union must be scalar")
	}
	return rawUnionWidth(meta.Union, depth)
}

func encodeRawUnion(buf *bytes.Buffer, enc *ua.BinaryEncoder, field RawField, depth int) error {
	width, err := rawUnionFieldWidth(RawFieldMeta{
		Type: field.Type, MaxStringLength: field.MaxStringLength, ValueRank: field.ValueRank,
		ArrayDimensions: field.ArrayDimensions, OptionSetLength: field.OptionSetLength,
		Structure: field.Structure, Union: field.Union,
	}, depth)
	if err != nil {
		return err
	}
	value, ok := field.Value.(RawUnion)
	if !ok || value.SwitchField > uint32(len(field.Union.Fields)) {
		return fmt.Errorf("invalid RawData Union value")
	}
	if value.SwitchField == 0 && value.Value != nil || value.SwitchField != 0 && value.Value == nil {
		return fmt.Errorf("RawData Union switch and value mismatch")
	}
	if buf.Len()+width > maxRawMessageBytes {
		return fmt.Errorf("RawData Union exceeds message size limit")
	}
	if err := enc.WriteUInt32(value.SwitchField); err != nil {
		return err
	}
	maximum := width - 4
	if value.SwitchField == 0 {
		buf.Write(make([]byte, maximum))
		return nil
	}
	selected := field.Union.Fields[value.SwitchField-1]
	selectedWidth, err := rawStructureFieldWidth(selected.Field, depth)
	if err != nil {
		return err
	}
	if err := encodeRawStructureField(buf, enc, selected.Field, value.Value, depth); err != nil {
		return fmt.Errorf("RawData Union field %q: %w", selected.Name, err)
	}
	buf.Write(make([]byte, maximum-selectedWidth))
	return nil
}

func decodeRawUnion(dec *ua.BinaryDecoder, reader *bytes.Reader, meta RawFieldMeta, depth int) (RawUnion, error) {
	width, err := rawUnionFieldWidth(meta, depth)
	if err != nil {
		return RawUnion{}, err
	}
	if reader.Len() < width {
		return RawUnion{}, fmt.Errorf("truncated RawData Union")
	}
	var switchField uint32
	if err := dec.ReadUInt32(&switchField); err != nil {
		return RawUnion{}, err
	}
	if switchField > uint32(len(meta.Union.Fields)) {
		return RawUnion{}, fmt.Errorf("RawData Union switch is out of range")
	}
	result := RawUnion{SwitchField: switchField}
	selectedWidth := 0
	if switchField != 0 {
		selected := meta.Union.Fields[switchField-1]
		selectedWidth, err = rawStructureFieldWidth(selected.Field, depth)
		if err != nil {
			return RawUnion{}, err
		}
		result.Value, err = decodeRawStructureField(dec, reader, selected.Field, depth)
		if err != nil {
			return RawUnion{}, fmt.Errorf("RawData Union field %q: %w", selected.Name, err)
		}
	}
	padding := make([]byte, width-4-selectedWidth)
	if _, err := io.ReadFull(reader, padding); err != nil {
		return RawUnion{}, err
	}
	for _, b := range padding {
		if b != 0 {
			return RawUnion{}, fmt.Errorf("nonzero RawData Union padding")
		}
	}
	return result, nil
}

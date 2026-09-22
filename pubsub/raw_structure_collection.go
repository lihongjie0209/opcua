package pubsub

import (
	"bytes"
	"fmt"

	"github.com/awcullen/opcua/ua"
)

func rawStructureCollectionLayout(meta RawFieldMeta, depth int) (int, int, error) {
	if meta.Type != RawStructureType || meta.MaxStringLength != 0 || meta.OptionSetLength != 0 || meta.Union != nil {
		return 0, 0, fmt.Errorf("invalid RawData Structure collection metadata")
	}
	width, err := rawStructureWidth(meta.Structure, depth)
	if err != nil {
		return 0, 0, err
	}
	if meta.ValueRank == 1 {
		if len(meta.ArrayDimensions) != 1 || meta.ArrayDimensions[0] == 0 || meta.ArrayDimensions[0] > uint32((maxRawMessageBytes-4)/width) {
			return 0, 0, fmt.Errorf("invalid RawData Structure array metadata")
		}
		return width, int(meta.ArrayDimensions[0]), nil
	}
	if meta.ValueRank < 2 || meta.ValueRank > 16 || len(meta.ArrayDimensions) != int(meta.ValueRank) {
		return 0, 0, fmt.Errorf("invalid RawData Structure matrix metadata")
	}
	limit := (maxRawMessageBytes - 4 - 4*int(meta.ValueRank)) / width
	maximum := 1
	for _, dimension := range meta.ArrayDimensions {
		if dimension == 0 || dimension > uint32(limit/maximum) {
			return 0, 0, fmt.Errorf("RawData Structure matrix exceeds size limit")
		}
		maximum *= int(dimension)
	}
	return width, maximum, nil
}

func rawStructureElementField(field RawField, value any) RawField {
	return RawField{Type: RawStructureType, Value: value, Structure: field.Structure}
}

func rawStructureElementMeta(meta RawFieldMeta) RawFieldMeta {
	return RawFieldMeta{Type: RawStructureType, Structure: meta.Structure}
}

func encodeRawStructureArray(buf *bytes.Buffer, enc *ua.BinaryEncoder, field RawField, depth int) error {
	meta := RawFieldMeta{Type: field.Type, ValueRank: field.ValueRank, ArrayDimensions: field.ArrayDimensions, Structure: field.Structure}
	width, maximum, err := rawStructureCollectionLayout(meta, depth)
	if err != nil || field.ValueRank != 1 {
		return fmt.Errorf("invalid RawData Structure array metadata")
	}
	var values []any
	if field.Value != nil {
		var ok bool
		values, ok = field.Value.([]any)
		if !ok {
			return fmt.Errorf("RawData Structure array value must be []any")
		}
	}
	if len(values) > maximum || buf.Len()+4+maximum*width > maxRawMessageBytes {
		return fmt.Errorf("RawData Structure array exceeds size limit")
	}
	count := int32(len(values))
	if values == nil {
		count = -1
	}
	if err := enc.WriteInt32(count); err != nil {
		return err
	}
	for i, value := range values {
		if err := encodeRawStructure(buf, enc, rawStructureElementField(field, value), depth); err != nil {
			return fmt.Errorf("RawData Structure array element %d: %w", i, err)
		}
	}
	buf.Write(make([]byte, (maximum-len(values))*width))
	return nil
}

func decodeRawStructureArray(dec *ua.BinaryDecoder, reader *bytes.Reader, meta RawFieldMeta, depth int) ([]any, error) {
	width, maximum, err := rawStructureCollectionLayout(meta, depth)
	if err != nil || meta.ValueRank != 1 || reader.Len() < 4+maximum*width {
		return nil, fmt.Errorf("invalid or truncated RawData Structure array")
	}
	var count int32
	if err := dec.ReadInt32(&count); err != nil {
		return nil, err
	}
	if count < -1 || count > int32(maximum) {
		return nil, fmt.Errorf("invalid RawData Structure array length")
	}
	actual := max(0, int(count))
	var values []any
	if count >= 0 {
		values = make([]any, actual)
	}
	elementMeta := rawStructureElementMeta(meta)
	for i := range values {
		value, err := decodeRawStructure(dec, reader, elementMeta, depth)
		if err != nil {
			return nil, fmt.Errorf("RawData Structure array element %d: %w", i, err)
		}
		values[i] = value
	}
	if err := readZeroPadding(reader, (maximum-actual)*width); err != nil {
		return nil, err
	}
	return values, nil
}

func encodeRawStructureMatrix(buf *bytes.Buffer, enc *ua.BinaryEncoder, field RawField, depth int) error {
	meta := RawFieldMeta{Type: field.Type, ValueRank: field.ValueRank, ArrayDimensions: field.ArrayDimensions, Structure: field.Structure}
	width, maximum, err := rawStructureCollectionLayout(meta, depth)
	if err != nil || field.ValueRank < 2 {
		return fmt.Errorf("invalid RawData Structure matrix metadata")
	}
	matrix, ok := field.Value.(RawMatrix)
	if !ok || len(matrix.Dimensions) != int(field.ValueRank) {
		return fmt.Errorf("RawData Structure matrix value or dimensions mismatch")
	}
	actualCount := 1
	for axis, dimension := range matrix.Dimensions {
		if dimension < 0 || uint32(dimension) > field.ArrayDimensions[axis] {
			return fmt.Errorf("RawData Structure matrix dimension %d exceeds ArrayDimensions", axis)
		}
		actualCount *= int(dimension)
	}
	if len(matrix.Values) != actualCount || buf.Len()+4+4*int(field.ValueRank)+maximum*width > maxRawMessageBytes {
		return fmt.Errorf("RawData Structure matrix value count or size mismatch")
	}
	if err := enc.WriteInt32(field.ValueRank); err != nil {
		return err
	}
	for _, dimension := range matrix.Dimensions {
		if err := enc.WriteInt32(dimension); err != nil {
			return err
		}
	}
	valueIndex := 0
	for position := 0; position < maximum; position++ {
		if !matrixCoordinatePresent(position, field.ArrayDimensions, matrix.Dimensions) {
			buf.Write(make([]byte, width))
			continue
		}
		if err := encodeRawStructure(buf, enc, rawStructureElementField(field, matrix.Values[valueIndex]), depth); err != nil {
			return fmt.Errorf("RawData Structure matrix element %d: %w", valueIndex, err)
		}
		valueIndex++
	}
	return nil
}

func decodeRawStructureMatrix(dec *ua.BinaryDecoder, reader *bytes.Reader, meta RawFieldMeta, depth int) (RawMatrix, error) {
	width, maximum, err := rawStructureCollectionLayout(meta, depth)
	if err != nil || meta.ValueRank < 2 || reader.Len() < 4+4*int(meta.ValueRank)+maximum*width {
		return RawMatrix{}, fmt.Errorf("invalid or truncated RawData Structure matrix")
	}
	var rank int32
	if err := dec.ReadInt32(&rank); err != nil || rank != meta.ValueRank {
		return RawMatrix{}, fmt.Errorf("RawData Structure matrix rank mismatch")
	}
	matrix := RawMatrix{Dimensions: make([]int32, int(rank))}
	actualCount := 1
	for axis := range matrix.Dimensions {
		if err := dec.ReadInt32(&matrix.Dimensions[axis]); err != nil {
			return RawMatrix{}, err
		}
		if matrix.Dimensions[axis] < 0 || uint32(matrix.Dimensions[axis]) > meta.ArrayDimensions[axis] {
			return RawMatrix{}, fmt.Errorf("RawData Structure matrix dimension %d exceeds ArrayDimensions", axis)
		}
		actualCount *= int(matrix.Dimensions[axis])
	}
	matrix.Values = make([]any, 0, actualCount)
	elementMeta := rawStructureElementMeta(meta)
	for position := 0; position < maximum; position++ {
		if !matrixCoordinatePresent(position, meta.ArrayDimensions, matrix.Dimensions) {
			if err := readZeroPadding(reader, width); err != nil {
				return RawMatrix{}, err
			}
			continue
		}
		value, err := decodeRawStructure(dec, reader, elementMeta, depth)
		if err != nil {
			return RawMatrix{}, fmt.Errorf("RawData Structure matrix element %d: %w", len(matrix.Values), err)
		}
		matrix.Values = append(matrix.Values, value)
	}
	return matrix, nil
}

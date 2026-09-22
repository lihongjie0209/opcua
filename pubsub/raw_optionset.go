package pubsub

import (
	"bytes"
	"fmt"
	"io"

	"github.com/awcullen/opcua/ua"
)

func rawOptionSetWidth(length uint32) (int, error) {
	if length == 0 || length > (maxRawMessageBytes-8)/2 {
		return 0, fmt.Errorf("invalid RawData OptionSet length")
	}
	return 8 + 2*int(length), nil
}

func encodeRawOptionSet(buf *bytes.Buffer, enc *ua.BinaryEncoder, field RawField) error {
	width, err := rawOptionSetWidth(field.OptionSetLength)
	if err != nil {
		return err
	}
	if field.ValueRank != 0 && field.ValueRank != -1 || len(field.ArrayDimensions) != 0 || field.MaxStringLength != 0 {
		return fmt.Errorf("RawData OptionSet must be scalar")
	}
	if buf.Len()+width > maxRawMessageBytes {
		return fmt.Errorf("RawData OptionSet exceeds message size limit")
	}
	return encodeRawOptionSetValue(enc, field.Value, field.OptionSetLength)
}

func decodeRawOptionSet(dec *ua.BinaryDecoder, reader *bytes.Reader, meta RawFieldMeta) (RawOptionSet, error) {
	width, err := rawOptionSetWidth(meta.OptionSetLength)
	if err != nil {
		return RawOptionSet{}, err
	}
	if meta.ValueRank != 0 && meta.ValueRank != -1 || len(meta.ArrayDimensions) != 0 || meta.MaxStringLength != 0 {
		return RawOptionSet{}, fmt.Errorf("RawData OptionSet must be scalar")
	}
	if reader.Len() < width {
		return RawOptionSet{}, fmt.Errorf("truncated RawData OptionSet")
	}
	return decodeRawOptionSetValue(dec, meta.OptionSetLength)
}

func encodeRawOptionSetValue(enc *ua.BinaryEncoder, raw any, length uint32) error {
	value, ok := raw.(RawOptionSet)
	if !ok || len(value.Value) != int(length) || len(value.ValidBits) != int(length) {
		return fmt.Errorf("RawData OptionSet value length mismatch")
	}
	return enc.Encode(ua.OptionSet{Value: ua.ByteString(value.Value), ValidBits: ua.ByteString(value.ValidBits)})
}

func decodeRawOptionSetValue(dec *ua.BinaryDecoder, length uint32) (RawOptionSet, error) {
	var value ua.OptionSet
	if err := dec.Decode(&value); err != nil {
		return RawOptionSet{}, err
	}
	if len(value.Value) != int(length) || len(value.ValidBits) != int(length) {
		return RawOptionSet{}, fmt.Errorf("RawData OptionSet value length mismatch")
	}
	return RawOptionSet{Value: append([]byte(nil), []byte(value.Value)...), ValidBits: append([]byte(nil), []byte(value.ValidBits)...)}, nil
}

func rawOptionSetCollectionLayout(meta RawFieldMeta) (int, int, error) {
	width, err := rawOptionSetWidth(meta.OptionSetLength)
	if err != nil || meta.MaxStringLength != 0 || meta.Structure != nil || meta.Union != nil {
		return 0, 0, fmt.Errorf("invalid RawData OptionSet collection metadata")
	}
	if meta.ValueRank == 1 {
		if len(meta.ArrayDimensions) != 1 || meta.ArrayDimensions[0] == 0 || meta.ArrayDimensions[0] > uint32((maxRawMessageBytes-4)/width) {
			return 0, 0, fmt.Errorf("invalid RawData OptionSet array metadata")
		}
		return width, int(meta.ArrayDimensions[0]), nil
	}
	if meta.ValueRank < 2 || meta.ValueRank > 16 || len(meta.ArrayDimensions) != int(meta.ValueRank) {
		return 0, 0, fmt.Errorf("invalid RawData OptionSet matrix metadata")
	}
	limit := (maxRawMessageBytes - 4 - 4*int(meta.ValueRank)) / width
	maximum := 1
	for _, dimension := range meta.ArrayDimensions {
		if dimension == 0 || dimension > uint32(limit/maximum) {
			return 0, 0, fmt.Errorf("RawData OptionSet matrix exceeds size limit")
		}
		maximum *= int(dimension)
	}
	return width, maximum, nil
}

func encodeRawOptionSetArray(buf *bytes.Buffer, enc *ua.BinaryEncoder, field RawField) error {
	meta := RawFieldMeta{Type: field.Type, ValueRank: field.ValueRank, ArrayDimensions: field.ArrayDimensions, OptionSetLength: field.OptionSetLength, Structure: field.Structure, Union: field.Union}
	width, maximum, err := rawOptionSetCollectionLayout(meta)
	if err != nil || field.ValueRank != 1 {
		return fmt.Errorf("invalid RawData OptionSet array metadata")
	}
	var values []any
	if field.Value != nil {
		var ok bool
		values, ok = field.Value.([]any)
		if !ok {
			return fmt.Errorf("RawData OptionSet array value must be []any")
		}
	}
	if len(values) > maximum || buf.Len()+4+maximum*width > maxRawMessageBytes {
		return fmt.Errorf("RawData OptionSet array exceeds size limit")
	}
	count := int32(len(values))
	if values == nil {
		count = -1
	}
	if err := enc.WriteInt32(count); err != nil {
		return err
	}
	for i, value := range values {
		if err := encodeRawOptionSetValue(enc, value, field.OptionSetLength); err != nil {
			return fmt.Errorf("RawData OptionSet array element %d: %w", i, err)
		}
	}
	buf.Write(make([]byte, (maximum-len(values))*width))
	return nil
}

func decodeRawOptionSetArray(dec *ua.BinaryDecoder, reader *bytes.Reader, meta RawFieldMeta) ([]any, error) {
	width, maximum, err := rawOptionSetCollectionLayout(meta)
	if err != nil || meta.ValueRank != 1 || reader.Len() < 4+maximum*width {
		return nil, fmt.Errorf("invalid or truncated RawData OptionSet array")
	}
	var count int32
	if err := dec.ReadInt32(&count); err != nil {
		return nil, err
	}
	if count < -1 || count > int32(maximum) {
		return nil, fmt.Errorf("invalid RawData OptionSet array length")
	}
	actual := max(0, int(count))
	var values []any
	if count >= 0 {
		values = make([]any, actual)
	}
	for i := range values {
		value, err := decodeRawOptionSetValue(dec, meta.OptionSetLength)
		if err != nil {
			return nil, fmt.Errorf("RawData OptionSet array element %d: %w", i, err)
		}
		values[i] = value
	}
	if err := readZeroPadding(reader, (maximum-actual)*width); err != nil {
		return nil, err
	}
	return values, nil
}

func encodeRawOptionSetMatrix(buf *bytes.Buffer, enc *ua.BinaryEncoder, field RawField) error {
	meta := RawFieldMeta{Type: field.Type, ValueRank: field.ValueRank, ArrayDimensions: field.ArrayDimensions, OptionSetLength: field.OptionSetLength, Structure: field.Structure, Union: field.Union}
	width, maximum, err := rawOptionSetCollectionLayout(meta)
	if err != nil || field.ValueRank < 2 {
		return fmt.Errorf("invalid RawData OptionSet matrix metadata")
	}
	matrix, ok := field.Value.(RawMatrix)
	if !ok || len(matrix.Dimensions) != int(field.ValueRank) {
		return fmt.Errorf("RawData OptionSet matrix value or dimensions mismatch")
	}
	actualCount := 1
	for axis, dimension := range matrix.Dimensions {
		if dimension < 0 || uint32(dimension) > field.ArrayDimensions[axis] {
			return fmt.Errorf("RawData OptionSet matrix dimension %d exceeds ArrayDimensions", axis)
		}
		actualCount *= int(dimension)
	}
	if len(matrix.Values) != actualCount || buf.Len()+4+4*int(field.ValueRank)+maximum*width > maxRawMessageBytes {
		return fmt.Errorf("RawData OptionSet matrix value count or size mismatch")
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
		if err := encodeRawOptionSetValue(enc, matrix.Values[valueIndex], field.OptionSetLength); err != nil {
			return fmt.Errorf("RawData OptionSet matrix element %d: %w", valueIndex, err)
		}
		valueIndex++
	}
	return nil
}

func decodeRawOptionSetMatrix(dec *ua.BinaryDecoder, reader *bytes.Reader, meta RawFieldMeta) (RawMatrix, error) {
	width, maximum, err := rawOptionSetCollectionLayout(meta)
	if err != nil || meta.ValueRank < 2 || reader.Len() < 4+4*int(meta.ValueRank)+maximum*width {
		return RawMatrix{}, fmt.Errorf("invalid or truncated RawData OptionSet matrix")
	}
	var rank int32
	if err := dec.ReadInt32(&rank); err != nil || rank != meta.ValueRank {
		return RawMatrix{}, fmt.Errorf("RawData OptionSet matrix rank mismatch")
	}
	matrix := RawMatrix{Dimensions: make([]int32, int(rank))}
	actualCount := 1
	for axis := range matrix.Dimensions {
		if err := dec.ReadInt32(&matrix.Dimensions[axis]); err != nil {
			return RawMatrix{}, err
		}
		if matrix.Dimensions[axis] < 0 || uint32(matrix.Dimensions[axis]) > meta.ArrayDimensions[axis] {
			return RawMatrix{}, fmt.Errorf("RawData OptionSet matrix dimension %d exceeds ArrayDimensions", axis)
		}
		actualCount *= int(matrix.Dimensions[axis])
	}
	matrix.Values = make([]any, 0, actualCount)
	for position := 0; position < maximum; position++ {
		if !matrixCoordinatePresent(position, meta.ArrayDimensions, matrix.Dimensions) {
			if err := readZeroPadding(reader, width); err != nil {
				return RawMatrix{}, err
			}
			continue
		}
		value, err := decodeRawOptionSetValue(dec, meta.OptionSetLength)
		if err != nil {
			return RawMatrix{}, fmt.Errorf("RawData OptionSet matrix element %d: %w", len(matrix.Values), err)
		}
		matrix.Values = append(matrix.Values, value)
	}
	return matrix, nil
}

func readZeroPadding(reader *bytes.Reader, size int) error {
	padding := make([]byte, size)
	if _, err := io.ReadFull(reader, padding); err != nil {
		return err
	}
	for _, value := range padding {
		if value != 0 {
			return fmt.Errorf("nonzero RawData padding")
		}
	}
	return nil
}

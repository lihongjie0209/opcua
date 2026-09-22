package pubsub

import (
	"bytes"
	"fmt"
	"io"

	"github.com/awcullen/opcua/ua"
)

// RawMatrix is a flattened, row-major RawData inline matrix.
type RawMatrix struct {
	Dimensions []int32
	Values     []any
}

func rawMatrixLayout(typ RawType, rank int32, dimensions []uint32, maxStringLength uint32) (int, int, error) {
	if rank < 2 || rank > 16 || len(dimensions) != int(rank) {
		return 0, 0, fmt.Errorf("unsupported RawData matrix rank")
	}
	width := rawFixedWidth(typ)
	if typ == RawString || typ == RawByteString {
		if maxStringLength == 0 || maxStringLength > maxRawMessageBytes-4 {
			return 0, 0, fmt.Errorf("invalid RawData matrix maximum string length")
		}
		width = 4 + int(maxStringLength)
	} else if maxStringLength != 0 {
		return 0, 0, fmt.Errorf("unexpected RawData matrix maximum string length")
	}
	if width == 0 {
		return 0, 0, fmt.Errorf("unsupported RawData matrix element type")
	}
	limit := (maxRawMessageBytes - 4 - 4*int(rank)) / width
	maximum := 1
	for _, dimension := range dimensions {
		if dimension == 0 || dimension > uint32(limit/maximum) {
			return 0, 0, fmt.Errorf("RawData matrix exceeds size limit")
		}
		maximum *= int(dimension)
	}
	return width, maximum, nil
}

func matrixCoordinatePresent(index int, maximum []uint32, actual []int32) bool {
	for axis := len(maximum) - 1; axis >= 0; axis-- {
		coordinate := index % int(maximum[axis])
		if coordinate >= int(actual[axis]) {
			return false
		}
		index /= int(maximum[axis])
	}
	return true
}

func encodeRawMatrix(buf *bytes.Buffer, enc *ua.BinaryEncoder, field RawField) error {
	width, maximum, err := rawMatrixLayout(field.Type, field.ValueRank, field.ArrayDimensions, field.MaxStringLength)
	if err != nil {
		return err
	}
	if buf.Len()+4+4*int(field.ValueRank)+maximum*width > maxRawMessageBytes {
		return fmt.Errorf("RawData matrix exceeds message size limit")
	}
	matrix, ok := field.Value.(RawMatrix)
	if !ok || len(matrix.Dimensions) != int(field.ValueRank) {
		return fmt.Errorf("RawData matrix value or dimensions mismatch")
	}
	actualCount := 1
	for axis, dimension := range matrix.Dimensions {
		if dimension < 0 || uint32(dimension) > field.ArrayDimensions[axis] {
			return fmt.Errorf("RawData matrix dimension %d exceeds ArrayDimensions", axis)
		}
		actualCount *= int(dimension)
	}
	if len(matrix.Values) != actualCount {
		return fmt.Errorf("RawData matrix value count mismatch")
	}
	if err := enc.WriteInt32(field.ValueRank); err != nil {
		return err
	}
	for _, dimension := range matrix.Dimensions {
		if err := enc.WriteInt32(dimension); err != nil {
			return err
		}
	}
	zeroSlot := make([]byte, width)
	valueIndex := 0
	for position := 0; position < maximum; position++ {
		if !matrixCoordinatePresent(position, field.ArrayDimensions, matrix.Dimensions) {
			buf.Write(zeroSlot)
			continue
		}
		value := matrix.Values[valueIndex]
		valueIndex++
		if err := writeRawMatrixElement(buf, enc, field, value); err != nil {
			return fmt.Errorf("RawData matrix element %d: %w", valueIndex-1, err)
		}
	}
	return nil
}

func writeRawMatrixElement(buf *bytes.Buffer, enc *ua.BinaryEncoder, field RawField, value any) error {
	if field.Type == RawString && value == "" {
		if err := enc.WriteInt32(0); err != nil {
			return err
		}
	} else if field.Type == RawByteString {
		if bytesValue, ok := value.([]byte); ok && len(bytesValue) == 0 {
			if err := enc.WriteInt32(0); err != nil {
				return err
			}
		} else if err := writeRawField(enc, RawField{Type: field.Type, Value: value, MaxStringLength: field.MaxStringLength}); err != nil {
			return err
		}
	} else if err := writeRawField(enc, RawField{Type: field.Type, Value: value, MaxStringLength: field.MaxStringLength}); err != nil {
		return err
	}
	if field.Type == RawString || field.Type == RawByteString {
		actual := 0
		switch v := value.(type) {
		case string:
			actual = len(v)
		case []byte:
			actual = len(v)
		}
		buf.Write(make([]byte, int(field.MaxStringLength)-actual))
	}
	return nil
}

func decodeRawMatrix(dec *ua.BinaryDecoder, reader *bytes.Reader, meta RawFieldMeta) (RawMatrix, error) {
	width, maximum, err := rawMatrixLayout(meta.Type, meta.ValueRank, meta.ArrayDimensions, meta.MaxStringLength)
	if err != nil {
		return RawMatrix{}, err
	}
	if reader.Len() < 4+4*int(meta.ValueRank)+maximum*width {
		return RawMatrix{}, fmt.Errorf("truncated RawData matrix")
	}
	var rank int32
	if err := dec.ReadInt32(&rank); err != nil {
		return RawMatrix{}, err
	}
	if rank != meta.ValueRank {
		return RawMatrix{}, fmt.Errorf("RawData matrix rank mismatch")
	}
	matrix := RawMatrix{Dimensions: make([]int32, int(rank))}
	actualCount := 1
	for axis := range matrix.Dimensions {
		if err := dec.ReadInt32(&matrix.Dimensions[axis]); err != nil {
			return RawMatrix{}, err
		}
		if matrix.Dimensions[axis] < 0 || uint32(matrix.Dimensions[axis]) > meta.ArrayDimensions[axis] {
			return RawMatrix{}, fmt.Errorf("RawData matrix dimension %d exceeds ArrayDimensions", axis)
		}
		actualCount *= int(matrix.Dimensions[axis])
	}
	matrix.Values = make([]any, 0, actualCount)
	padding := make([]byte, width)
	for position := 0; position < maximum; position++ {
		if !matrixCoordinatePresent(position, meta.ArrayDimensions, matrix.Dimensions) {
			if _, err := io.ReadFull(reader, padding); err != nil {
				return RawMatrix{}, err
			}
			for _, b := range padding {
				if b != 0 {
					return RawMatrix{}, fmt.Errorf("nonzero RawData matrix padding")
				}
			}
			continue
		}
		var value any
		if meta.Type == RawString || meta.Type == RawByteString {
			value, err = readPaddedStringArrayElement(dec, reader, meta)
		} else {
			value, err = readRawField(dec, meta.Type)
		}
		if err != nil {
			return RawMatrix{}, fmt.Errorf("RawData matrix element %d: %w", len(matrix.Values), err)
		}
		matrix.Values = append(matrix.Values, value)
	}
	return matrix, nil
}

package pubsub

import (
	"bytes"
	"fmt"
	"io"

	"github.com/awcullen/opcua/ua"
)

func rawFixedWidth(typ RawType) int {
	switch typ {
	case RawBoolean, RawSByte, RawByte:
		return 1
	case RawInt16, RawUInt16:
		return 2
	case RawInt32, RawUInt32, RawFloat, RawStatusCode:
		return 4
	case RawInt64, RawUInt64, RawDouble, RawDateTime:
		return 8
	case RawGUID:
		return 16
	default:
		return 0
	}
}

func rawArrayLayout(typ RawType, rank int32, dimensions []uint32, maxStringLength uint32) (int, int, error) {
	width := rawFixedWidth(typ)
	if typ == RawString || typ == RawByteString {
		if maxStringLength == 0 || maxStringLength > maxRawMessageBytes-4 {
			return 0, 0, fmt.Errorf("unsupported or oversized RawData array metadata")
		}
		width = 4 + int(maxStringLength)
	} else if maxStringLength != 0 {
		return 0, 0, fmt.Errorf("unsupported or oversized RawData array metadata")
	}
	if rank != 1 || len(dimensions) != 1 || dimensions[0] == 0 || width == 0 ||
		dimensions[0] > uint32((maxRawMessageBytes-4)/width) {
		return 0, 0, fmt.Errorf("unsupported or oversized RawData array metadata")
	}
	return width, int(dimensions[0]), nil
}

func encodeRawArray(buf *bytes.Buffer, enc *ua.BinaryEncoder, field RawField) error {
	width, maximum, err := rawArrayLayout(field.Type, field.ValueRank, field.ArrayDimensions, field.MaxStringLength)
	if err != nil {
		return err
	}
	if buf.Len()+4+maximum*width > maxRawMessageBytes {
		return fmt.Errorf("RawData array exceeds message size limit")
	}
	var values []any
	if field.Value != nil {
		var ok bool
		values, ok = field.Value.([]any)
		if !ok {
			return fmt.Errorf("RawData array value must be []any")
		}
	}
	if len(values) > maximum {
		return fmt.Errorf("RawData array length exceeds ArrayDimensions")
	}
	count := int32(len(values))
	if values == nil {
		count = -1
	}
	if err := enc.WriteInt32(count); err != nil {
		return err
	}
	for i, value := range values {
		var writeErr error
		if field.Type == RawString && value == "" {
			writeErr = enc.WriteInt32(0)
		} else if field.Type == RawByteString {
			if bytesValue, ok := value.([]byte); ok && len(bytesValue) == 0 {
				writeErr = enc.WriteInt32(0)
			} else {
				writeErr = writeRawField(enc, RawField{Type: field.Type, Value: value, MaxStringLength: field.MaxStringLength})
			}
		} else {
			writeErr = writeRawField(enc, RawField{Type: field.Type, Value: value, MaxStringLength: field.MaxStringLength})
		}
		if writeErr != nil {
			return fmt.Errorf("RawData array element %d: %w", i, writeErr)
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
	}
	buf.Write(make([]byte, (maximum-len(values))*width))
	return nil
}

func decodeRawArray(dec *ua.BinaryDecoder, reader *bytes.Reader, meta RawFieldMeta) ([]any, error) {
	width, maximum, err := rawArrayLayout(meta.Type, meta.ValueRank, meta.ArrayDimensions, meta.MaxStringLength)
	if err != nil {
		return nil, err
	}
	if 4+maximum*width > reader.Len() {
		return nil, fmt.Errorf("truncated RawData array")
	}
	var count int32
	if err := dec.ReadInt32(&count); err != nil {
		return nil, err
	}
	if count < -1 || count > int32(maximum) {
		return nil, fmt.Errorf("invalid RawData array length")
	}
	actual := int(count)
	if actual < 0 {
		actual = 0
	}
	var values []any
	if count >= 0 {
		values = make([]any, actual)
	}
	for i := 0; i < actual; i++ {
		var value any
		var err error
		if meta.Type == RawString || meta.Type == RawByteString {
			value, err = readPaddedStringArrayElement(dec, reader, meta)
		} else {
			value, err = readRawField(dec, meta.Type)
		}
		if err != nil {
			return nil, fmt.Errorf("RawData array element %d: %w", i, err)
		}
		values[i] = value
	}
	padding := make([]byte, (maximum-actual)*width)
	if _, err := io.ReadFull(reader, padding); err != nil {
		return nil, err
	}
	for _, b := range padding {
		if b != 0 {
			return nil, fmt.Errorf("nonzero RawData array padding")
		}
	}
	return values, nil
}

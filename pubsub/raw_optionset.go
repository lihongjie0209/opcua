package pubsub

import (
	"bytes"
	"fmt"

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
	value, ok := field.Value.(RawOptionSet)
	if !ok || len(value.Value) != int(field.OptionSetLength) || len(value.ValidBits) != int(field.OptionSetLength) {
		return fmt.Errorf("RawData OptionSet value length mismatch")
	}
	if buf.Len()+width > maxRawMessageBytes {
		return fmt.Errorf("RawData OptionSet exceeds message size limit")
	}
	return enc.Encode(ua.OptionSet{Value: ua.ByteString(value.Value), ValidBits: ua.ByteString(value.ValidBits)})
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
	var value ua.OptionSet
	if err := dec.Decode(&value); err != nil {
		return RawOptionSet{}, err
	}
	if len(value.Value) != int(meta.OptionSetLength) || len(value.ValidBits) != int(meta.OptionSetLength) {
		return RawOptionSet{}, fmt.Errorf("RawData OptionSet value length mismatch")
	}
	return RawOptionSet{Value: append([]byte(nil), []byte(value.Value)...), ValidBits: append([]byte(nil), []byte(value.ValidBits)...)}, nil
}

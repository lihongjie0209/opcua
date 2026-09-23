package pubsub

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type JSONMetadataField struct {
	Name            string
	BuiltInType     uint8
	DataType        string
	ValueRank       int32
	ArrayDimensions []uint32
}

type JSONMetadataAnnouncement struct {
	MessageID         string
	PublisherID       string
	DataSetWriterID   uint16
	WriterGroupName   string
	DataSetWriterName string
	Timestamp         string
	MetaData          json.RawMessage
	DataSetName       string
	MajorVersion      uint32
	MinorVersion      uint32
	Fields            []JSONMetadataField
}

type jsonMetadataEnvelope struct {
	MessageID         string          `json:"MessageId"`
	MessageType       string          `json:"MessageType"`
	PublisherID       string          `json:"PublisherId"`
	DataSetWriterID   *uint16         `json:"DataSetWriterId"`
	WriterGroupName   string          `json:"WriterGroupName"`
	DataSetWriterName string          `json:"DataSetWriterName"`
	Timestamp         string          `json:"Timestamp"`
	Metadata          json.RawMessage `json:"MetaData"`
}

type jsonDataSetMetadata struct {
	Name                 string            `json:"Name"`
	Fields               []json.RawMessage `json:"Fields"`
	ConfigurationVersion json.RawMessage   `json:"ConfigurationVersion"`
}

type jsonMetadataField struct {
	Name            string   `json:"Name"`
	BuiltInType     *uint8   `json:"BuiltInType"`
	DataType        string   `json:"DataType"`
	ValueRank       *int32   `json:"ValueRank"`
	ArrayDimensions []uint32 `json:"ArrayDimensions"`
}

func DecodeJSONMetadata(wire []byte) (JSONMetadataAnnouncement, error) {
	if err := validateJSONDocument(wire); err != nil {
		return JSONMetadataAnnouncement{}, err
	}
	var envelope jsonMetadataEnvelope
	if err := decodeJSONObject(bytes.TrimSpace(wire), &envelope); err != nil {
		return JSONMetadataAnnouncement{}, err
	}
	if envelope.MessageID == "" || envelope.MessageType != "ua-metadata" || envelope.PublisherID == "" || envelope.DataSetWriterID == nil || envelope.WriterGroupName == "" || envelope.DataSetWriterName == "" || envelope.Timestamp == "" {
		return JSONMetadataAnnouncement{}, errors.New("PubSub metadata requires complete ua-metadata envelope")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, envelope.Timestamp)
	if err != nil {
		return JSONMetadataAnnouncement{}, fmt.Errorf("invalid PubSub metadata UTC Timestamp %q", envelope.Timestamp)
	}
	_, offset := timestamp.Zone()
	if offset != 0 {
		return JSONMetadataAnnouncement{}, fmt.Errorf("invalid PubSub metadata UTC Timestamp %q", envelope.Timestamp)
	}
	if len(envelope.Metadata) == 0 || bytes.Equal(envelope.Metadata, []byte("null")) {
		return JSONMetadataAnnouncement{}, errors.New("PubSub MetaData object is required")
	}
	var metadata jsonDataSetMetadata
	if err = unmarshalMetadataObject(envelope.Metadata, &metadata); err != nil {
		return JSONMetadataAnnouncement{}, fmt.Errorf("MetaData: %w", err)
	}
	if metadata.Name == "" || len(metadata.Fields) == 0 || len(metadata.Fields) > MaxJSONDataSetFields {
		return JSONMetadataAnnouncement{}, fmt.Errorf("MetaData requires Name and 1..%d Fields", MaxJSONDataSetFields)
	}
	var version struct {
		MajorVersion *uint32 `json:"MajorVersion"`
		MinorVersion *uint32 `json:"MinorVersion"`
	}
	if err = unmarshalMetadataObject(metadata.ConfigurationVersion, &version); err != nil {
		return JSONMetadataAnnouncement{}, fmt.Errorf("ConfigurationVersion: %w", err)
	}
	if version.MajorVersion == nil || version.MinorVersion == nil {
		return JSONMetadataAnnouncement{}, errors.New("ConfigurationVersion requires MajorVersion and MinorVersion")
	}
	result := JSONMetadataAnnouncement{
		MessageID: envelope.MessageID, PublisherID: envelope.PublisherID, DataSetWriterID: *envelope.DataSetWriterID,
		WriterGroupName: envelope.WriterGroupName, DataSetWriterName: envelope.DataSetWriterName, Timestamp: envelope.Timestamp,
		MetaData: bytes.Clone(envelope.Metadata), DataSetName: metadata.Name, MajorVersion: *version.MajorVersion, MinorVersion: *version.MinorVersion,
		Fields: make([]JSONMetadataField, len(metadata.Fields)),
	}
	seen := make(map[string]struct{}, len(metadata.Fields))
	for index, raw := range metadata.Fields {
		var field jsonMetadataField
		if err = unmarshalMetadataObject(raw, &field); err != nil {
			return JSONMetadataAnnouncement{}, fmt.Errorf("field %d: %w", index, err)
		}
		if field.Name == "" || field.BuiltInType == nil || *field.BuiltInType < 1 || *field.BuiltInType > 25 || field.DataType == "" || field.ValueRank == nil || *field.ValueRank < -3 {
			return JSONMetadataAnnouncement{}, fmt.Errorf("field %d lacks valid Name, BuiltInType, DataType, or ValueRank", index)
		}
		if _, exists := seen[field.Name]; exists {
			return JSONMetadataAnnouncement{}, fmt.Errorf("duplicate metadata field name %q", field.Name)
		}
		seen[field.Name] = struct{}{}
		if *field.ValueRank > 0 && len(field.ArrayDimensions) != int(*field.ValueRank) || *field.ValueRank <= 0 && len(field.ArrayDimensions) != 0 {
			return JSONMetadataAnnouncement{}, fmt.Errorf("field %d ArrayDimensions do not match ValueRank", index)
		}
		result.Fields[index] = JSONMetadataField{Name: field.Name, BuiltInType: *field.BuiltInType, DataType: field.DataType, ValueRank: *field.ValueRank, ArrayDimensions: append([]uint32(nil), field.ArrayDimensions...)}
	}
	return result, nil
}

func EncodeJSONMetadata(message JSONMetadataAnnouncement) ([]byte, error) {
	writerID := message.DataSetWriterID
	wire, err := json.Marshal(jsonMetadataEnvelope{
		MessageID: message.MessageID, MessageType: "ua-metadata", PublisherID: message.PublisherID,
		DataSetWriterID: &writerID, WriterGroupName: message.WriterGroupName, DataSetWriterName: message.DataSetWriterName,
		Timestamp: message.Timestamp, Metadata: message.MetaData,
	})
	if err != nil {
		return nil, err
	}
	if _, err = DecodeJSONMetadata(wire); err != nil {
		return nil, err
	}
	return wire, nil
}

func unmarshalMetadataObject(wire []byte, target any) error {
	if len(wire) == 0 || wire[0] != '{' {
		return errors.New("PubSub metadata value must be an object")
	}
	return json.Unmarshal(wire, target)
}

package pubsub

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	MaxJSONNetworkMessageBytes = 1 << 20
	MaxJSONDataSetMessages     = 64
	MaxJSONDataSetFields       = 1024
	MaxJSONNestingDepth        = 64
)

type JSONNetworkMessage struct {
	MessageID       string
	MessageType     string
	PublisherID     string
	WriterGroupName string
	Messages        []JSONDataSetMessage
}

type JSONDataSetMessage struct {
	DataSetWriterID uint16
	SequenceNumber  uint32
	MessageType     string
	MetaDataVersion *JSONConfigurationVersion
	Payload         map[string]json.RawMessage
}

type JSONConfigurationVersion struct {
	MajorVersion uint32 `json:"MajorVersion"`
	MinorVersion uint32 `json:"MinorVersion"`
}

type jsonNetworkEnvelope struct {
	MessageID       string          `json:"MessageId"`
	MessageType     string          `json:"MessageType"`
	PublisherID     string          `json:"PublisherId"`
	WriterGroupName string          `json:"WriterGroupName"`
	Messages        json.RawMessage `json:"Messages"`
}

type jsonDataSetEnvelope struct {
	DataSetWriterID *uint16         `json:"DataSetWriterId"`
	SequenceNumber  *uint32         `json:"SequenceNumber"`
	MessageType     string          `json:"MessageType"`
	MetaDataVersion json.RawMessage `json:"MetaDataVersion,omitempty"`
	Payload         json.RawMessage `json:"Payload,omitempty"`
}

func DecodeJSONNetworkMessage(wire []byte) (JSONNetworkMessage, error) {
	if err := validateJSONDocument(wire); err != nil {
		return JSONNetworkMessage{}, err
	}
	var envelope jsonNetworkEnvelope
	if err := decodeJSONObject(wire, &envelope); err != nil {
		return JSONNetworkMessage{}, err
	}
	if len(envelope.Messages) == 0 || bytes.Equal(envelope.Messages, []byte("null")) {
		return JSONNetworkMessage{}, errors.New("PubSub Messages must be an object or array")
	}
	var entries []json.RawMessage
	switch envelope.Messages[0] {
	case '{':
		entries = []json.RawMessage{envelope.Messages}
	case '[':
		if err := json.Unmarshal(envelope.Messages, &entries); err != nil {
			return JSONNetworkMessage{}, err
		}
	default:
		return JSONNetworkMessage{}, errors.New("PubSub Messages must be an object or array")
	}
	if len(entries) == 0 || len(entries) > MaxJSONDataSetMessages {
		return JSONNetworkMessage{}, fmt.Errorf("PubSub Messages count must be 1..%d", MaxJSONDataSetMessages)
	}
	message := JSONNetworkMessage{MessageID: envelope.MessageID, MessageType: envelope.MessageType, PublisherID: envelope.PublisherID, WriterGroupName: envelope.WriterGroupName, Messages: make([]JSONDataSetMessage, len(entries))}
	for index, entry := range entries {
		var dataset jsonDataSetEnvelope
		if err := decodeJSONObject(entry, &dataset); err != nil {
			return JSONNetworkMessage{}, fmt.Errorf("DataSetMessage %d: %w", index, err)
		}
		if dataset.DataSetWriterID == nil || dataset.SequenceNumber == nil {
			return JSONNetworkMessage{}, fmt.Errorf("DataSetMessage %d needs writer ID and sequence", index)
		}
		item := JSONDataSetMessage{DataSetWriterID: *dataset.DataSetWriterID, SequenceNumber: *dataset.SequenceNumber, MessageType: dataset.MessageType}
		if len(dataset.MetaDataVersion) != 0 {
			var version struct {
				MajorVersion *uint32 `json:"MajorVersion"`
				MinorVersion *uint32 `json:"MinorVersion"`
			}
			if err := decodeJSONObject(dataset.MetaDataVersion, &version); err != nil || version.MajorVersion == nil || version.MinorVersion == nil {
				if err == nil {
					err = errors.New("requires both versions")
				}
				return JSONNetworkMessage{}, fmt.Errorf("DataSetMessage %d MetaDataVersion: %w", index, err)
			}
			item.MetaDataVersion = &JSONConfigurationVersion{MajorVersion: *version.MajorVersion, MinorVersion: *version.MinorVersion}
		}
		if len(dataset.Payload) != 0 {
			if err := decodeJSONObject(dataset.Payload, &item.Payload); err != nil {
				return JSONNetworkMessage{}, fmt.Errorf("DataSetMessage %d Payload: %w", index, err)
			}
			for name, raw := range item.Payload {
				item.Payload[name] = bytes.Clone(raw)
			}
		}
		message.Messages[index] = item
	}
	if err := validateJSONNetworkMessage(message); err != nil {
		return JSONNetworkMessage{}, err
	}
	return message, nil
}

func EncodeJSONNetworkMessage(message JSONNetworkMessage) ([]byte, error) {
	if err := validateJSONNetworkMessage(message); err != nil {
		return nil, err
	}
	entries := make([]jsonDataSetEnvelope, len(message.Messages))
	for index, item := range message.Messages {
		entries[index] = jsonDataSetEnvelope{DataSetWriterID: &item.DataSetWriterID, SequenceNumber: &item.SequenceNumber, MessageType: item.MessageType}
		var err error
		if item.MetaDataVersion != nil {
			entries[index].MetaDataVersion, err = json.Marshal(item.MetaDataVersion)
		}
		if err == nil && item.Payload != nil {
			entries[index].Payload, err = json.Marshal(item.Payload)
		}
		if err != nil {
			return nil, fmt.Errorf("DataSetMessage %d: %w", index, err)
		}
	}
	var messages []byte
	var err error
	if len(entries) == 1 {
		messages, err = json.Marshal(entries[0])
	} else {
		messages, err = json.Marshal(entries)
	}
	if err != nil {
		return nil, err
	}
	wire, err := json.Marshal(jsonNetworkEnvelope{MessageID: message.MessageID, MessageType: message.MessageType, PublisherID: message.PublisherID, WriterGroupName: message.WriterGroupName, Messages: messages})
	if err != nil {
		return nil, err
	}
	if err = validateJSONDocument(wire); err != nil {
		return nil, err
	}
	return wire, nil
}

func validateJSONNetworkMessage(message JSONNetworkMessage) error {
	if message.MessageID == "" || message.MessageType != "ua-data" || message.PublisherID == "" || message.WriterGroupName == "" {
		return errors.New("PubSub message requires MessageId, ua-data type, PublisherId, and WriterGroupName")
	}
	if len(message.Messages) == 0 || len(message.Messages) > MaxJSONDataSetMessages {
		return fmt.Errorf("PubSub Messages count must be 1..%d", MaxJSONDataSetMessages)
	}
	for index, item := range message.Messages {
		switch item.MessageType {
		case "ua-keyframe", "ua-deltaframe", "ua-event":
			if item.Payload == nil {
				return fmt.Errorf("DataSetMessage %d requires Payload", index)
			}
		case "ua-keepalive":
			if item.Payload != nil {
				return fmt.Errorf("DataSetMessage %d keepalive must omit Payload", index)
			}
		default:
			return fmt.Errorf("DataSetMessage %d has unsupported MessageType %q", index, item.MessageType)
		}
		if len(item.Payload) > MaxJSONDataSetFields {
			return fmt.Errorf("DataSetMessage %d exceeds %d fields", index, MaxJSONDataSetFields)
		}
	}
	return nil
}

func decodeJSONObject(wire []byte, destination any) error {
	if len(wire) == 0 || wire[0] != '{' {
		return errors.New("PubSub JSON value must be an object")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing PubSub JSON value")
	}
	return nil
}

// DecodeJSONObject decodes exactly one JSON object, rejects unknown fields,
// and leaves duplicate-key rejection to ValidateJSONDocument when decoding an
// untrusted complete document.
func DecodeJSONObject(wire []byte, destination any) error {
	return decodeJSONObject(wire, destination)
}

func validateJSONDocument(wire []byte) error {
	if len(wire) == 0 || len(wire) > MaxJSONNetworkMessageBytes {
		return fmt.Errorf("PubSub JSON message must be 1..%d bytes", MaxJSONNetworkMessageBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	if err := scanUniqueJSON(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing PubSub JSON value")
	}
	return nil
}

// ValidateJSONDocument enforces the PubSub JSON byte/depth bounds, rejects
// duplicate object keys at every level, and requires one complete value.
func ValidateJSONDocument(wire []byte) error {
	return validateJSONDocument(wire)
}

func scanUniqueJSON(decoder *json.Decoder, depth int) error {
	if depth > MaxJSONNestingDepth {
		return fmt.Errorf("PubSub JSON nesting exceeds %d", MaxJSONNestingDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	opening, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch opening {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("PubSub JSON object has a non-string key")
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("duplicate PubSub JSON key %q", key)
			}
			keys[key] = struct{}{}
			if err = scanUniqueJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err = scanUniqueJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected PubSub JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}

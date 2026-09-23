package pubsub

import (
	"encoding/json"
	"testing"
)

func TestJSONNetworkMessageStrictRoundTrip(t *testing.T) {
	wire := []byte(`{"MessageId":"m","MessageType":"ua-data","PublisherId":"p","WriterGroupName":"g","Messages":{"DataSetWriterId":7,"SequenceNumber":9,"MessageType":"ua-keyframe","MetaDataVersion":{"MajorVersion":1,"MinorVersion":2},"Payload":{"count":9007199254740993}}}`)
	message, err := DecodeJSONNetworkMessage(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(message.Messages) != 1 || message.Messages[0].DataSetWriterID != 7 || string(message.Messages[0].Payload["count"]) != "9007199254740993" {
		t.Fatalf("message=%#v", message)
	}
	encoded, err := EncodeJSONNetworkMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err = json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
}

func TestJSONNetworkMessageRejectsMalformed(t *testing.T) {
	tests := [][]byte{
		[]byte(`{"MessageId":"m","MessageId":"again","MessageType":"ua-data","PublisherId":"p","WriterGroupName":"g","Messages":{}}`),
		[]byte(`{"MessageId":"m","MessageType":"ua-data","PublisherId":"p","WriterGroupName":"g","unknown":1,"Messages":{}}`),
		[]byte(`{"MessageId":"m","MessageType":"ua-data","PublisherId":"p","WriterGroupName":"g","Messages":{"DataSetWriterId":7,"SequenceNumber":9,"MessageType":"ua-keepalive","Payload":{}}}`),
	}
	for _, wire := range tests {
		if _, err := DecodeJSONNetworkMessage(wire); err == nil {
			t.Fatalf("accepted %s", wire)
		}
	}
}

func TestStrictJSONDocumentAndObjectAPI(t *testing.T) {
	if err := ValidateJSONDocument([]byte(`{"a":1,"a":2}`)); err == nil {
		t.Fatal("duplicate key accepted")
	}
	var value struct {
		A int `json:"a"`
	}
	if err := DecodeJSONObject([]byte(`{"a":1}`), &value); err != nil || value.A != 1 {
		t.Fatalf("value=%#v error=%v", value, err)
	}
	if err := DecodeJSONObject([]byte(`{"a":1,"b":2}`), &value); err == nil {
		t.Fatal("unknown field accepted")
	}
}

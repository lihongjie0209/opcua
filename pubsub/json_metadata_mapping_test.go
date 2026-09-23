package pubsub

import (
	"testing"
)

const validJSONMetadata = `{"MessageId":"meta-1","MessageType":"ua-metadata","PublisherId":"p","DataSetWriterId":7,"WriterGroupName":"g","DataSetWriterName":"w","Timestamp":"2026-09-24T00:00:00Z","MetaData":{"Name":"set","Fields":[{"Name":"temperature","BuiltInType":10,"DataType":"i=10","ValueRank":-1,"ArrayDimensions":[]}],"ConfigurationVersion":{"MajorVersion":1,"MinorVersion":2}}}`

func TestJSONMetadataStrictRoundTrip(t *testing.T) {
	message, err := DecodeJSONMetadata([]byte(validJSONMetadata))
	if err != nil {
		t.Fatal(err)
	}
	if message.DataSetWriterID != 7 || message.DataSetName != "set" || message.MajorVersion != 1 || len(message.Fields) != 1 || message.Fields[0].Name != "temperature" {
		t.Fatalf("message=%#v", message)
	}
	wire, err := EncodeJSONMetadata(message)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeJSONMetadata(wire); err != nil {
		t.Fatal(err)
	}
}

func TestJSONMetadataRejectsMalformed(t *testing.T) {
	tests := []string{
		`{"MessageId":"meta-1","MessageType":"ua-data","PublisherId":"p","DataSetWriterId":7,"WriterGroupName":"g","DataSetWriterName":"w","Timestamp":"2026-09-24T00:00:00Z","MetaData":{}}`,
		`{"MessageId":"meta-1","MessageType":"ua-metadata","PublisherId":"p","DataSetWriterId":7,"WriterGroupName":"g","DataSetWriterName":"w","Timestamp":"2026-09-24T01:00:00+01:00","MetaData":{"Name":"set","Fields":[],"ConfigurationVersion":{"MajorVersion":1,"MinorVersion":2}}}`,
		`{"MessageId":"meta-1","MessageType":"ua-metadata","PublisherId":"p","DataSetWriterId":7,"WriterGroupName":"g","DataSetWriterName":"w","Timestamp":"2026-09-24T00:00:00Z","MetaData":{"Name":"set","Fields":[{"Name":"x","BuiltInType":10,"DataType":"i=10","ValueRank":-1,"ArrayDimensions":[]},{"Name":"x","BuiltInType":10,"DataType":"i=10","ValueRank":-1,"ArrayDimensions":[]}],"ConfigurationVersion":{"MajorVersion":1,"MinorVersion":2}}}`,
	}
	for _, wire := range tests {
		if _, err := DecodeJSONMetadata([]byte(wire)); err == nil {
			t.Fatalf("accepted %s", wire)
		}
	}
}

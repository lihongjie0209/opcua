package ua

// NullableString preserves the distinction between a null and an empty OPC UA
// String when exact Variant decoding is requested.
type NullableString struct {
	Value string
	Null  bool
}

// NullableByteString preserves the distinction between null and empty bytes.
type NullableByteString struct {
	Value []byte
	Null  bool
}

// NullableXMLElement preserves the distinction between a null and empty XML
// element without interpreting the XML body.
type NullableXMLElement struct {
	Value string
	Null  bool
}

// RawDateTime preserves the signed 100 ns tick count exactly as encoded.
type RawDateTime int64

// RawGUID preserves the 16 encoded GUID bytes without UUID field reordering.
type RawGUID [16]byte

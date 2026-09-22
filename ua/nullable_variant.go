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

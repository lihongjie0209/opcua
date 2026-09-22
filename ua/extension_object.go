// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

// ExtensionObject stores a struct.
// Register the struct type and id with the BinaryEncoder using
//
//	func RegisterBinaryEncodingID(typ reflect.Type, id ExpandedNodeID)
type ExtensionObject any

// RawExtensionObject preserves an ExtensionObject body whose concrete type is
// unknown to the type registry. Encoding is 0 (none), 1 (binary), or 2 (XML).
type RawExtensionObject struct {
	TypeID    NodeID
	RawTypeID *RawNodeID
	Encoding  byte
	Body      []byte
}

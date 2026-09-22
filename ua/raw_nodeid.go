package ua

import (
	"io"
)

// RawNodeIDKind identifies an exact NodeId identifier representation.
type RawNodeIDKind byte

const (
	RawNodeIDNumeric RawNodeIDKind = iota
	RawNodeIDString
	RawNodeIDGUID
	RawNodeIDOpaque
)

// RawNodeID preserves nullable identifiers and encoded GUID bytes.
type RawNodeID struct {
	Kind           RawNodeIDKind
	NamespaceIndex uint16
	Numeric        uint32
	String         NullableString
	GUID           RawGUID
	Opaque         NullableByteString
}

// RawExpandedNodeID preserves optional expansion flags and their exact values.
type RawExpandedNodeID struct {
	NodeID              RawNodeID
	NamespaceURIPresent bool
	NamespaceURI        NullableString
	ServerIndexPresent  bool
	ServerIndex         uint32
}

// RawQualifiedName preserves a nullable versus empty name.
type RawQualifiedName struct {
	NamespaceIndex uint16
	Name           NullableString
}

func (enc *BinaryEncoder) writeRawNodeID(value RawNodeID, flags byte) error {
	switch value.Kind {
	case RawNodeIDNumeric:
		switch {
		case value.NamespaceIndex == 0 && value.Numeric <= 255:
			if err := enc.WriteByte(flags); err != nil {
				return BadEncodingError
			}
			return enc.WriteByte(byte(value.Numeric))
		case value.NamespaceIndex <= 255 && value.Numeric <= 65535:
			if err := enc.WriteByte(1 | flags); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteByte(byte(value.NamespaceIndex)); err != nil {
				return BadEncodingError
			}
			return enc.WriteUInt16(uint16(value.Numeric))
		default:
			if err := enc.WriteByte(2 | flags); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteUInt16(value.NamespaceIndex); err != nil {
				return BadEncodingError
			}
			return enc.WriteUInt32(value.Numeric)
		}
	case RawNodeIDString:
		if err := enc.WriteByte(3 | flags); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt16(value.NamespaceIndex); err != nil {
			return BadEncodingError
		}
		return enc.writeNullableString(value.String)
	case RawNodeIDGUID:
		if err := enc.WriteByte(4 | flags); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt16(value.NamespaceIndex); err != nil {
			return BadEncodingError
		}
		_, err := enc.w.Write(value.GUID[:])
		if err != nil {
			return BadEncodingError
		}
		return nil
	case RawNodeIDOpaque:
		if err := enc.WriteByte(5 | flags); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt16(value.NamespaceIndex); err != nil {
			return BadEncodingError
		}
		return enc.writeNullableBytes(value.Opaque)
	default:
		return BadEncodingError
	}
}

func (enc *BinaryEncoder) writeNullableString(value NullableString) error {
	if value.Null {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value.Value))); err != nil {
		return BadEncodingError
	}
	if _, err := enc.w.Write([]byte(value.Value)); err != nil {
		return BadEncodingError
	}
	return nil
}

func (enc *BinaryEncoder) writeNullableBytes(value NullableByteString) error {
	if value.Null {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value.Value))); err != nil {
		return BadEncodingError
	}
	if _, err := enc.w.Write(value.Value); err != nil {
		return BadEncodingError
	}
	return nil
}

func (dec *BinaryDecoder) readRawNodeID(expanded bool) (RawNodeID, byte, error) {
	var encoding byte
	if err := dec.ReadByte(&encoding); err != nil {
		return RawNodeID{}, 0, BadDecodingError
	}
	flags := encoding & 0xc0
	if !expanded && flags != 0 {
		return RawNodeID{}, 0, BadDecodingError
	}
	kind := encoding & 0x3f
	var value RawNodeID
	switch kind {
	case 0:
		var id byte
		if err := dec.ReadByte(&id); err != nil {
			return RawNodeID{}, 0, BadDecodingError
		}
		value.Kind, value.Numeric = RawNodeIDNumeric, uint32(id)
	case 1:
		var ns byte
		var id uint16
		if err := dec.ReadByte(&ns); err != nil {
			return RawNodeID{}, 0, BadDecodingError
		}
		if err := dec.ReadUInt16(&id); err != nil {
			return RawNodeID{}, 0, BadDecodingError
		}
		value.Kind, value.NamespaceIndex, value.Numeric = RawNodeIDNumeric, uint16(ns), uint32(id)
	case 2:
		value.Kind = RawNodeIDNumeric
		if err := dec.ReadUInt16(&value.NamespaceIndex); err != nil {
			return RawNodeID{}, 0, BadDecodingError
		}
		if err := dec.ReadUInt32(&value.Numeric); err != nil {
			return RawNodeID{}, 0, BadDecodingError
		}
	case 3:
		value.Kind = RawNodeIDString
		if err := dec.ReadUInt16(&value.NamespaceIndex); err != nil {
			return RawNodeID{}, 0, BadDecodingError
		}
		text, err := dec.readNullableString()
		if err != nil {
			return RawNodeID{}, 0, err
		}
		value.String = text
	case 4:
		value.Kind = RawNodeIDGUID
		if err := dec.ReadUInt16(&value.NamespaceIndex); err != nil {
			return RawNodeID{}, 0, BadDecodingError
		}
		if _, err := io.ReadFull(dec.r, value.GUID[:]); err != nil {
			return RawNodeID{}, 0, BadDecodingError
		}
	case 5:
		value.Kind = RawNodeIDOpaque
		if err := dec.ReadUInt16(&value.NamespaceIndex); err != nil {
			return RawNodeID{}, 0, BadDecodingError
		}
		bytes, err := dec.readNullableBytes()
		if err != nil {
			return RawNodeID{}, 0, err
		}
		value.Opaque = bytes
	default:
		return RawNodeID{}, 0, BadDecodingError
	}
	return value, flags, nil
}

func (dec *BinaryDecoder) readNullableString() (NullableString, error) {
	bytes, null, err := dec.readNullableSequence()
	return NullableString{Value: string(bytes), Null: null}, err
}

func (dec *BinaryDecoder) readNullableBytes() (NullableByteString, error) {
	bytes, null, err := dec.readNullableSequence()
	return NullableByteString{Value: bytes, Null: null}, err
}

func (dec *BinaryDecoder) readNullableSequence() ([]byte, bool, error) {
	var length int32
	if err := dec.ReadInt32(&length); err != nil || length < -1 {
		return nil, false, BadDecodingError
	}
	if length == -1 {
		return nil, true, nil
	}
	value := make([]byte, length)
	if _, err := io.ReadFull(dec.r, value); err != nil {
		return nil, false, BadDecodingError
	}
	return value, false, nil
}

package pubsub

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unicode/utf8"

	"github.com/awcullen/opcua/ua"
)

const maxDiagnosticInfoDepth = 10

type diagnosticPresence struct {
	additionalNull bool
	inner          *diagnosticPresence
}

// EncodeExactDiagnosticInfo encodes a bounded canonical DiagnosticInfo with
// the mature UA Binary encoder.
func EncodeExactDiagnosticInfo(value ua.DiagnosticInfo) ([]byte, error) {
	normalized, err := normalizeDiagnosticInfo(value, 1, make(map[*ua.DiagnosticInfo]bool))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	encoder := ua.NewBinaryEncoder(&buf, ua.NewEncodingContext())
	if err := encoder.WriteDiagnosticInfo(normalized); err != nil {
		return nil, err
	}
	if buf.Len() > maxUADPDynamicPayloadBytes {
		return nil, errors.New("DiagnosticInfo exceeds 65535 bytes")
	}
	return append([]byte(nil), buf.Bytes()...), nil
}

// DecodeExactDiagnosticInfoPrefix decodes one bounded canonical
// DiagnosticInfo prefix and reports the bytes consumed.
func DecodeExactDiagnosticInfoPrefix(wire []byte) (ua.DiagnosticInfo, int, error) {
	if len(wire) == 0 || len(wire) > maxUADPDynamicPayloadBytes {
		return ua.DiagnosticInfo{}, 0, errors.New("DiagnosticInfo size is invalid")
	}
	consumed, presence, err := validateDiagnosticInfoWire(wire, 1)
	if err != nil {
		return ua.DiagnosticInfo{}, 0, err
	}
	reader := bytes.NewReader(wire[:consumed])
	decoder := ua.NewBinaryDecoder(reader, ua.NewEncodingContext())
	var value ua.DiagnosticInfo
	if err := decoder.ReadDiagnosticInfo(&value); err != nil || reader.Len() != 0 {
		return ua.DiagnosticInfo{}, 0, errors.New("invalid DiagnosticInfo encoding")
	}
	canonicalizeDecodedDiagnosticInfo(&value, presence)
	return value, consumed, nil
}

func normalizeDiagnosticInfo(value ua.DiagnosticInfo, depth int, seen map[*ua.DiagnosticInfo]bool) (ua.DiagnosticInfo, error) {
	if depth > maxDiagnosticInfoDepth {
		return ua.DiagnosticInfo{}, errors.New("DiagnosticInfo recursion limit exceeded")
	}
	result := value
	for _, index := range []*int32{result.SymbolicID, result.NamespaceURI, result.Locale, result.LocalizedText} {
		if index != nil && *index < -1 {
			return ua.DiagnosticInfo{}, errors.New("DiagnosticInfo string-table index is below -1")
		}
	}
	if result.SymbolicID != nil && *result.SymbolicID == -1 {
		result.SymbolicID = nil
	}
	if result.NamespaceURI != nil && *result.NamespaceURI == -1 {
		result.NamespaceURI = nil
	}
	if result.Locale != nil && *result.Locale == -1 {
		result.Locale = nil
	}
	if result.LocalizedText != nil && *result.LocalizedText == -1 {
		result.LocalizedText = nil
	}
	if result.AdditionalInfo != nil && (!utf8.ValidString(*result.AdditionalInfo) || len(*result.AdditionalInfo) > maxUADPDynamicPayloadBytes) {
		return ua.DiagnosticInfo{}, errors.New("invalid DiagnosticInfo AdditionalInfo")
	}
	if result.InnerStatusCode != nil && *result.InnerStatusCode == 0 {
		result.InnerStatusCode = nil
	}
	if result.InnerDiagnosticInfo != nil {
		if seen[result.InnerDiagnosticInfo] {
			return ua.DiagnosticInfo{}, errors.New("cyclic DiagnosticInfo")
		}
		seen[result.InnerDiagnosticInfo] = true
		inner, err := normalizeDiagnosticInfo(*result.InnerDiagnosticInfo, depth+1, seen)
		delete(seen, result.InnerDiagnosticInfo)
		if err != nil {
			return ua.DiagnosticInfo{}, err
		}
		result.InnerDiagnosticInfo = &inner
	}
	return result, nil
}

func validateDiagnosticInfoWire(wire []byte, depth int) (int, *diagnosticPresence, error) {
	if depth > maxDiagnosticInfoDepth || len(wire) == 0 || wire[0]&0x80 != 0 {
		return 0, nil, errors.New("invalid DiagnosticInfo mask or recursion depth")
	}
	mask, offset := wire[0], 1
	read := func(size int) ([]byte, error) {
		if len(wire)-offset < size {
			return nil, errors.New("truncated DiagnosticInfo")
		}
		part := wire[offset : offset+size]
		offset += size
		return part, nil
	}
	for _, bit := range []byte{1, 2, 8, 4} {
		if mask&bit == 0 {
			continue
		}
		part, err := read(4)
		if err != nil {
			return 0, nil, err
		}
		if int32(binary.LittleEndian.Uint32(part)) < -1 {
			return 0, nil, errors.New("invalid DiagnosticInfo string-table index")
		}
	}
	presence := &diagnosticPresence{}
	if mask&16 != 0 {
		part, err := read(4)
		if err != nil {
			return 0, nil, err
		}
		length := int32(binary.LittleEndian.Uint32(part))
		if length < -1 || length > maxUADPDynamicPayloadBytes {
			return 0, nil, errors.New("invalid DiagnosticInfo AdditionalInfo length")
		}
		presence.additionalNull = length == -1
		if length >= 0 {
			part, err = read(int(length))
			if err != nil {
				return 0, nil, err
			}
			if !utf8.Valid(part) {
				return 0, nil, errors.New("invalid DiagnosticInfo AdditionalInfo UTF-8")
			}
		}
	}
	if mask&32 != 0 {
		if _, err := read(4); err != nil {
			return 0, nil, err
		}
	}
	if mask&64 != 0 {
		used, inner, err := validateDiagnosticInfoWire(wire[offset:], depth+1)
		if err != nil {
			return 0, nil, err
		}
		offset += used
		presence.inner = inner
	}
	return offset, presence, nil
}

func canonicalizeDecodedDiagnosticInfo(value *ua.DiagnosticInfo, presence *diagnosticPresence) {
	for _, target := range []**int32{&value.SymbolicID, &value.NamespaceURI, &value.Locale, &value.LocalizedText} {
		if *target != nil && **target == -1 {
			*target = nil
		}
	}
	if presence.additionalNull {
		value.AdditionalInfo = nil
	}
	if value.InnerStatusCode != nil && *value.InnerStatusCode == 0 {
		value.InnerStatusCode = nil
	}
	if value.InnerDiagnosticInfo != nil && presence.inner != nil {
		canonicalizeDecodedDiagnosticInfo(value.InnerDiagnosticInfo, presence.inner)
	}
}

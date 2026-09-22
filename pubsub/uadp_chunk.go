package pubsub

import (
	"encoding/binary"
	"errors"
	"sort"
)

const uadpChunkHeaderBytes = 23

// UADPChunk is one unsecured chunk NetworkMessage for one DataSetMessage.
type UADPChunk struct {
	PublisherID           uint64
	WriterID              uint16
	MessageSequenceNumber uint16
	ChunkOffset           uint32
	TotalSize             uint32
	Data                  []byte
}

// EncodeUADPChunk encodes one Part 14 chunk NetworkMessage using the dynamic
// UInt64 PublisherId profile.
func EncodeUADPChunk(chunk UADPChunk) ([]byte, error) {
	if err := validateUADPChunk(chunk); err != nil {
		return nil, err
	}
	wire := make([]byte, uadpChunkHeaderBytes+len(chunk.Data))
	wire[0], wire[1], wire[2] = 0xd1, 0x83, 0x01
	binary.LittleEndian.PutUint64(wire[3:], chunk.PublisherID)
	binary.LittleEndian.PutUint16(wire[11:], chunk.WriterID)
	binary.LittleEndian.PutUint16(wire[13:], chunk.MessageSequenceNumber)
	binary.LittleEndian.PutUint32(wire[15:], chunk.ChunkOffset)
	binary.LittleEndian.PutUint32(wire[19:], chunk.TotalSize)
	copy(wire[uadpChunkHeaderBytes:], chunk.Data)
	return wire, nil
}

// DecodeUADPChunk decodes and owns one unsecured chunk NetworkMessage.
func DecodeUADPChunk(wire []byte) (UADPChunk, error) {
	if len(wire) <= uadpChunkHeaderBytes || len(wire) > uadpChunkHeaderBytes+maxUADPDynamicPayloadBytes {
		return UADPChunk{}, errors.New("UADP chunk size is invalid")
	}
	if wire[0] != 0xd1 || wire[1] != 0x83 || wire[2] != 0x01 {
		return UADPChunk{}, errors.New("unsupported UADP chunk flags")
	}
	chunk := UADPChunk{
		PublisherID: binary.LittleEndian.Uint64(wire[3:]), WriterID: binary.LittleEndian.Uint16(wire[11:]),
		MessageSequenceNumber: binary.LittleEndian.Uint16(wire[13:]), ChunkOffset: binary.LittleEndian.Uint32(wire[15:]),
		TotalSize: binary.LittleEndian.Uint32(wire[19:]), Data: append([]byte(nil), wire[uadpChunkHeaderBytes:]...),
	}
	if err := validateUADPChunk(chunk); err != nil {
		return UADPChunk{}, err
	}
	return chunk, nil
}

// SplitUADPChunks splits one DataSetMessage into canonical equal-sized chunks,
// except for the final chunk, each no larger than maxNetworkMessageBytes.
func SplitUADPChunks(publisherID uint64, writerID, sequence uint16, message []byte, maxNetworkMessageBytes int) ([][]byte, error) {
	if writerID == 0 || len(message) == 0 || len(message) > maxUADPDynamicPayloadBytes {
		return nil, errors.New("UADP chunk source is invalid")
	}
	dataBytes := maxNetworkMessageBytes - uadpChunkHeaderBytes
	if dataBytes <= 0 || maxNetworkMessageBytes > uadpChunkHeaderBytes+maxUADPDynamicPayloadBytes {
		return nil, errors.New("UADP chunk network-message bound is invalid")
	}
	count := (len(message) + dataBytes - 1) / dataBytes
	result := make([][]byte, count)
	for index, offset := 0, 0; offset < len(message); index, offset = index+1, offset+dataBytes {
		end := min(offset+dataBytes, len(message))
		wire, err := EncodeUADPChunk(UADPChunk{PublisherID: publisherID, WriterID: writerID,
			MessageSequenceNumber: sequence, ChunkOffset: uint32(offset), TotalSize: uint32(len(message)), Data: message[offset:end]})
		if err != nil {
			return nil, err
		}
		result[index] = wire
	}
	return result, nil
}

// ReassembleUADPChunks validates and joins one complete, possibly out-of-order
// chunk set without mutating the caller's slice.
func ReassembleUADPChunks(chunks []UADPChunk) ([]byte, error) {
	if len(chunks) == 0 || len(chunks) > maxUADPDynamicPayloadBytes {
		return nil, errors.New("UADP chunk set size is invalid")
	}
	first := chunks[0]
	if err := validateUADPChunk(first); err != nil {
		return nil, err
	}
	ordered := append([]UADPChunk(nil), chunks...)
	for _, chunk := range ordered[1:] {
		if err := validateUADPChunk(chunk); err != nil {
			return nil, err
		}
		if chunk.PublisherID != first.PublisherID || chunk.WriterID != first.WriterID ||
			chunk.MessageSequenceNumber != first.MessageSequenceNumber || chunk.TotalSize != first.TotalSize {
			return nil, errors.New("UADP chunk selectors do not match")
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ChunkOffset < ordered[j].ChunkOffset })
	result := make([]byte, first.TotalSize)
	expectedOffset, regularSize := uint32(0), 0
	for index, chunk := range ordered {
		if chunk.ChunkOffset != expectedOffset {
			return nil, errors.New("UADP chunk set has a gap, overlap, or duplicate")
		}
		last := index == len(ordered)-1
		if !last {
			if regularSize == 0 {
				regularSize = len(chunk.Data)
			} else if len(chunk.Data) != regularSize {
				return nil, errors.New("non-final UADP chunks have different sizes")
			}
		} else if chunk.ChunkOffset+uint32(len(chunk.Data)) != first.TotalSize {
			return nil, errors.New("UADP chunk set is incomplete")
		}
		copy(result[chunk.ChunkOffset:], chunk.Data)
		expectedOffset += uint32(len(chunk.Data))
	}
	return result, nil
}

func validateUADPChunk(chunk UADPChunk) error {
	if chunk.WriterID == 0 || chunk.TotalSize == 0 || chunk.TotalSize > maxUADPDynamicPayloadBytes || len(chunk.Data) == 0 {
		return errors.New("UADP chunk metadata is invalid")
	}
	if chunk.ChunkOffset >= chunk.TotalSize || uint64(chunk.ChunkOffset)+uint64(len(chunk.Data)) > uint64(chunk.TotalSize) {
		return errors.New("UADP chunk range is invalid")
	}
	return nil
}

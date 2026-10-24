package proto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestFramesAreBounded(t *testing.T) {
	for _, size := range []uint32{0, MaxFrameBytes + 1, ^uint32(0)} {
		var input bytes.Buffer
		_ = binary.Write(&input, binary.BigEndian, size)
		if _, err := ReadFrame(&input); err == nil {
			t.Fatalf("accepted frame length %d", size)
		}
	}
	var encoded bytes.Buffer
	if err := WriteFrame(&encoded, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	data, err := ReadFrame(&encoded)
	if err != nil || string(data) != "hello" {
		t.Fatalf("round trip: %q %v", data, err)
	}
	if err := WriteFrame(&encoded, make([]byte, MaxFrameBytes+1)); err == nil {
		t.Fatal("oversized write accepted")
	}
}

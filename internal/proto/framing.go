package proto

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Bounds allocations even if a child is compromised or writes a corrupt frame.
// The HTTP command limit is 1 MiB; escaped output can be several times larger.
const MaxFrameBytes = 8 << 20

func ReadFrame(r io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if n == 0 || n > MaxFrameBytes {
		return nil, fmt.Errorf("frame length must be between 1 and %d bytes", MaxFrameBytes)
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > MaxFrameBytes {
		return fmt.Errorf("frame length must be between 1 and %d bytes", MaxFrameBytes)
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(payload))); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

package hashing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
)

// Known digests of harmless, generated inputs.
const (
	emptySHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	abcSHA   = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
)

func TestKnownDigests(t *testing.T) {
	for _, tc := range []struct{ in, want string }{{"", emptySHA}, {"abc", abcSHA}} {
		res, err := Sum(context.Background(), strings.NewReader(tc.in), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if res.Hex() != tc.want || res.Bytes != int64(len(tc.in)) {
			t.Errorf("Sum(%q) = %s/%d, want %s/%d", tc.in, res.Hex(), res.Bytes, tc.want, len(tc.in))
		}
	}
}

func TestLimitExact(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 1000)
	if _, err := Sum(context.Background(), bytes.NewReader(data), 1000); err != nil {
		t.Fatalf("exactly-at-limit input rejected: %v", err)
	}
	if _, err := Sum(context.Background(), bytes.NewReader(data), 999); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over-limit input: got %v, want ErrTooLarge", err)
	}
	if _, err := Sum(context.Background(), bytes.NewReader(nil), -1); err == nil {
		t.Fatal("negative limit accepted")
	}
}

func TestMultiChunkMatchesStdlib(t *testing.T) {
	data := make([]byte, 3*bufSize+17)
	for i := range data {
		data[i] = byte(i * 7)
	}
	res, err := Sum(context.Background(), bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if res.SHA256 != sha256.Sum256(data) {
		t.Fatal("digest mismatch with crypto/sha256")
	}
	if !bytes.Equal(res.Header, data[:HeaderSize]) {
		t.Fatal("header capture mismatch")
	}
}

func TestCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Sum(ctx, strings.NewReader("abc"), 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestReadError(t *testing.T) {
	if _, err := Sum(context.Background(), errReader{}, 10); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v", err)
	}
}

// zeroReader produces n zero bytes without allocating them up front.
type zeroReader struct{ n int64 }

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.n == 0 {
		return 0, io.EOF
	}
	k := min(int64(len(p)), z.n)
	clear(p[:k])
	z.n -= k
	return int(k), nil
}

// TestBoundedMemory hashes 256 MiB and checks that allocation stays far below
// the input size, i.e. the input is streamed rather than buffered.
func TestBoundedMemory(t *testing.T) {
	const size = 256 << 20
	h := NewHasher()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	res, err := h.Sum(context.Background(), &zeroReader{n: size}, size)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if res.Bytes != size {
		t.Fatalf("hashed %d bytes", res.Bytes)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 4<<20 {
		t.Fatalf("allocated %d bytes hashing %d; expected streaming", alloc, size)
	}
}

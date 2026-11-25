// Package hashing computes SHA-256 digests while streaming, with a hard byte
// limit and cooperative cancellation. It never buffers whole files: memory use
// is one fixed-size read buffer plus a small header capture.
package hashing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

// HeaderSize is the number of leading bytes captured for structural
// heuristics. Header bytes are never logged or written to reports.
const HeaderSize = 512

const bufSize = 64 << 10

// ErrTooLarge is returned when the input contains more bytes than allowed.
var ErrTooLarge = errors.New("input exceeds byte limit")

// Result is the outcome of hashing one stream.
type Result struct {
	SHA256 [sha256.Size]byte
	Bytes  int64
	// Header holds up to HeaderSize leading bytes, for heuristics only.
	Header []byte
}

// Hex returns the lowercase hexadecimal digest.
func (r Result) Hex() string { return hex.EncodeToString(r.SHA256[:]) }

// Hasher reuses its read buffer across calls. It is not safe for concurrent use.
type Hasher struct {
	buf []byte
}

// NewHasher returns a Hasher with a fixed-size read buffer.
func NewHasher() *Hasher { return &Hasher{buf: make([]byte, bufSize)} }

// Sum streams r through SHA-256, reading at most limit bytes. If r yields more
// than limit bytes, Sum returns ErrTooLarge without a digest. The context is
// checked before every read, so a cancelled scan stops within one buffer.
func (h *Hasher) Sum(ctx context.Context, r io.Reader, limit int64) (Result, error) {
	if limit < 0 {
		return Result{}, errors.New("hashing: negative limit")
	}
	d := sha256.New()
	header := make([]byte, 0, HeaderSize)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		n, err := r.Read(h.buf)
		if n > 0 {
			if int64(n) > limit-total {
				return Result{}, ErrTooLarge
			}
			d.Write(h.buf[:n])
			if room := HeaderSize - len(header); room > 0 {
				header = append(header, h.buf[:min(n, room)]...)
			}
			total += int64(n)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Result{}, err
		}
	}
	var res Result
	d.Sum(res.SHA256[:0])
	res.Bytes = total
	res.Header = header
	return res, nil
}

// Sum is a convenience wrapper using a fresh Hasher.
func Sum(ctx context.Context, r io.Reader, limit int64) (Result, error) {
	return NewHasher().Sum(ctx, r, limit)
}

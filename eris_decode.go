package eris

import (
	"bytes"
	"encoding/base32"
	"errors"
	"io"
)

// Storage fetches a block's encrypted bytes given a particular reference,
// or returns an error if it is unable to do so.
//
// The error is passed back up through the call to Decode.
type Storage interface {
	Get(ref [RefSize]byte) ([]byte, error)
}

// Decode streams decrypted content to the writer, using the Storage to fetch
// successive content-addressed encrypted blocks descendent of the root
// reference.
func Decode(s Storage, w io.Writer, root Ref) error {
	if err := checkBlockSize(root.BlockSize); err != nil {
		return err
	}
	// Insert our own middle-writer to keep a one-block buffer
	// in memory, so that the final block may have its padding
	// properly stripped
	sink := newPaddingSink(w, root.BlockSize)
	// Decode the tree.
	err := decodeRecur(s, sink, root.Level, root.Ref, root.Key, root.BlockSize)
	if err != nil {
		return err
	}
	// Strip the padding from the final content block.
	_, err = sink.Flush()
	return err
}

// decodeRecur applies a recursive depth-first decoding of the encoded tree.
func decodeRecur(s Storage, w io.Writer, level int, ref [RefSize]byte, key [KeySize]byte, size BlockSize) error {
	// 1. Obtain the Block of data
	eb, err := checkedGet(s, ref, size)
	if err != nil {
		return err
	}
	ub, err := decrypt(eb, key)
	if err != nil {
		return err
	}
	// 2. Determine whether this is a Content block or inner node.
	if level == 0 {
		// Content: Emit
		_, err = w.Write(ub)
		if err != nil {
			return err
		}
		return nil
	} else {
		// Inner node: Recur decoding the tree.
		bb := bytes.NewBuffer(ub)
		var rbuf [RefSize]byte
		var kbuf [KeySize]byte
		for {
			_, err = io.ReadFull(bb, rbuf[:])
			if err == io.EOF {
				// OK end-condition: We reach the end of the block
				return nil
			} else if err != nil {
				return err
			}
			_, err = io.ReadFull(bb, kbuf[:])
			if err != nil {
				return err
			}
			if refKeyPairAllZero(rbuf, kbuf) {
				// OK end-condition: Padded empty
				return nil
			}
			err = decodeRecur(s, w, level-1, rbuf, kbuf, size)
			if err != nil {
				return err
			}
		}
	}
}

// decrypt applies the symmetric key to decrypt in-place.
func decrypt(block ebytes, key [KeySize]byte) (ubytes, error) {
	c, err := newSymmKeyCipher(key)
	if err != nil {
		return nil, err
	}
	// Decrypt in-place
	c.XORKeyStream(block[:], block)
	return ubytes(block), nil
}

// checkedGet fetches the block from the storage, ensures the block is of the
// expected proper size, and then computes the returned encrypted data's hash
// to ensure the proper reference was indeed fetched by the Storage.
func checkedGet(s Storage, ref [RefSize]byte, size BlockSize) (eb ebytes, err error) {
	var b []byte
	b, err = s.Get(ref)
	if err != nil {
		return
	}
	eb = ebytes(b)
	// Quick check: ensure the block is the proper size
	if int(size) != len(eb) {
		err = errors.New("error fetching reference from Storage: returned block incorrect size")
		return
	}
	// Ensure the retrieved data matches
	ch := toRef(eb)
	for i := 0; i < RefSize; i++ {
		if ch[i] != ref[i] {
			err = errors.New("error fetching reference from Storage: returned block did not match reference=" +
				base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(ref[:]))
			return
		}
	}
	return
}

// refKeyPairAllZero returns true when both the reference and key bytes are all
// zero.
func refKeyPairAllZero(r [RefSize]byte, k [KeySize]byte) bool {
	for _, b := range r {
		if b != 0 {
			return false
		}
	}
	for _, b := range k {
		if b != 0 {
			return false
		}
	}
	return true
}

// checkBlockSize enforces that the given BlockSize is a supported one, or
// returns an error.
func checkBlockSize(bs BlockSize) error {
	switch bs {
	case Size1KiB:
		fallthrough
	case Size32KiB:
		return nil
	default:
		return errors.New("unhandled block size")
	}
}

// paddingSink is a single-buffered solution. It is a transparent pass-through
// writer for all blocks except the final one. The final block has its trailing
// padding stripped.
type paddingSink struct {
	w     io.Writer
	buf   []byte
	first bool
}

// newPaddingSink creates a new paddingSink.
func newPaddingSink(w io.Writer, size BlockSize) *paddingSink {
	return &paddingSink{
		w:     w,
		buf:   make([]byte, size),
		first: true,
	}
}

// Write copies the bytes into the sink's buffer.
//
// If it is already holding onto a block of data, it first flushes those bytes
// to the underlying writer.
func (p *paddingSink) Write(b []byte) (n int, err error) {
	if !p.first {
		n, err = p.w.Write(p.buf)
	}
	p.first = false
	if len(p.buf) != len(b) {
		return 0, errors.New("mismatched padding buffer and block size")
	}
	copy(p.buf, b)
	return len(p.buf), nil
}

// Flush applies the unpadding algorithm to the block within the sink's buffer.
func (p *paddingSink) Flush() (int, error) {
	idx := len(p.buf) - 1
	found := false
	for ; idx >= 0; idx-- {
		if p.buf[idx] == 0x80 {
			found = true
			break
		} else if p.buf[idx] != 0 {
			return 0, errors.New("content block padding malformed")
		}
	}
	if !found {
		return 0, errors.New("last content block was improperly padded")
	}
	if idx <= 0 {
		return 0, nil
	}
	return p.w.Write(p.buf[:idx])
}

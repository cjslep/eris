package eris

import (
	"bytes"
	"crypto/cipher"
	"encoding/base32"
	"errors"
	"hash"
	"io"
	"math"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
)

const (
	// Kibi, base 2, definition
	kb = 1024
	mb = kb * 1024
	gb = mb * 1024
)

const (
	RefSize = 32
	KeySize = 32
)

const (
	erisURNVersion = "erisx2"
)

type BlockSize int

const (
	Size1KiB  BlockSize = 1 * kb
	Size32KiB BlockSize = 32 * kb
)

type Ref struct {
	BlockSize BlockSize
	Level     int
	Ref       [RefSize]byte
	Key       [KeySize]byte
}

func (r Ref) URN() (string, error) {
	// Prepare read capability in binary form
	var bb bytes.Buffer
	if r.BlockSize == Size1KiB {
		bb.WriteByte(0)
	} else if r.BlockSize == Size32KiB {
		bb.WriteByte(1)
	} else {
		return "", errors.New("cannot create urn: unhandled block size")
	}
	if r.Level > math.MaxUint8 {
		return "", errors.New("cannot create urn: level exceeds 1 byte depth")
	}
	bb.WriteByte(byte(r.Level))
	bb.Write(r.Ref[:])
	bb.Write(r.Key[:])

	// Create the URN
	var b strings.Builder
	b.WriteString("urn:")
	b.WriteString(erisURNVersion)
	b.WriteString(":")
	b.WriteString(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bb.Bytes()))
	return b.String(), nil
}

// ebytes is an encrypted set of bytes
type ebytes []byte

// ubytes is an unencrypted set of bytes
type ubytes []byte

// Encode1KiB encodes bytes from the given Reader into 1 kibibyte blocks,
// emitting the blocks to the WriteFunc as data is streamed in from the
// Reader. This allows encoding arbitrarily large data in-memory.
//
// Returns the root reference block.
func Encode1KiB(w WriteFunc, r io.Reader, secret []byte) (ref Ref, err error) {
	return encode(w, r, secret, Size1KiB)
}

// Encode32KiB encodes bytes from the given Reader into 32 kibibyte blocks,
// emitting the blocks to the WriteFunc as data is streamed in from the
// Reader. This allows encoding arbitrarily large data in-memory.
//
// Returns the root reference block.
func Encode32KiB(w WriteFunc, r io.Reader, secret []byte) (ref Ref, err error) {
	return encode(w, r, secret, Size32KiB)
}

// encode encodes bytes into a requested arbitrarily sized block.
//
// Allocates a single buffer of block-size.
func encode(w WriteFunc, r io.Reader, secret []byte, size BlockSize) (ref Ref, err error) {
	ref.BlockSize = size
	var mFn marshalFn
	var acc *accumulator
	mFn, acc, err = newMarshaller(w, secret, size)
	buf := make([]byte, size)
	for {
		var n int
		n, err = io.ReadFull(r, buf)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			// Error reading.
			return
		} else if n == 0 && err == io.EOF || // Do special closing padding block, then terminate; or...
			err == io.ErrUnexpectedEOF { // ...pad current block, then terminate.
			buf = padContentBlock(buf[:n], size)
			err = mFn(buf)
			if err != nil {
				return
			}
			ref, err = acc.Flush()
			return
		} else {
			// Process block normally.
			err = mFn(buf)
			if err != nil {
				return
			}
		}
	}
}

// TL;DR: Strategy is to build the tree up recursively, growing in log-space
// memory requirements during single pass encoding.
func newMarshaller(w WriteFunc, secret []byte, size BlockSize) (marshalFn, *accumulator, error) {
	acc, err := newAccumulator(w, size, secret, 1, nil)
	if err != nil {
		return nil, nil, err
	}
	m := recurMarshalBlocks(w, secret, acc.RecurAccumulate)
	return m, acc, nil
}

type accumFn func(r [RefSize]byte, k [KeySize]byte) error
type marshalFn func(ublock ubytes) error
type WriteFunc func(eblock ebytes, ref [RefSize]byte, readkey [KeySize]byte) error

// accumulator is responsible for accumulating references to blocks in a layer
// below this accumulator. The accumulator is responsible for the recursive
// construction of a tree bottom-up. A single accumulator instance's lifetime
// will construct a single layer of the tree (all of a node and its siblings).
// As new layers above are needed, more accumulators are automatically created.
//
// Each accumulator allocates a single buffer of block-size.
type accumulator struct {
	W      WriteFunc
	Size   BlockSize
	Level  int
	Secret []byte
	// Set non-nil-once state
	Parent        *accumulator
	ParentMarshal marshalFn
	// mutable state
	RefKeyPairs []byte
	N           int
}

// newAccumulator creates a new accumulator with a properly-sized buffer.
//
// Enforces that the requested size is evenly divisible by RefSize + KeySize.
func newAccumulator(w WriteFunc, size BlockSize, secret []byte, level int, parent *accumulator) (*accumulator, error) {
	if size%(RefSize+KeySize) != 0 {
		return nil, errors.New("requested block size is not an even multiple of reference-key pair size")
	}
	return &accumulator{
		W:           w,
		Size:        size,
		Level:       level,
		Secret:      secret,
		Parent:      parent,
		RefKeyPairs: make([]byte, size),
		N:           0,
	}, nil
}

// reset the buffer and index.
func (a *accumulator) reset() {
	for i := 0; i < len(a.RefKeyPairs); i++ {
		a.RefKeyPairs[i] = 0
	}
	a.N = 0
}

// add the reference and key pair to the buffer, incrementing the index as
// needed.
func (a *accumulator) add(ref [RefSize]byte, key [KeySize]byte) {
	copy(a.RefKeyPairs[a.N:a.N+RefSize], ref[:])
	a.N += RefSize
	copy(a.RefKeyPairs[a.N:a.N+KeySize], key[:])
	a.N += KeySize
}

// RecurAccumulate accumulates reference-key pairs, forming a tree construction
// as needed.
//
// Assumes that (RefSize + KeySize) divides into Size evenly.
//
// Enforces that the buffer is never empty.
func (a *accumulator) RecurAccumulate(ref [RefSize]byte, key [KeySize]byte) error {
	if a.N == int(a.Size) {
		// We need to emit a complete block to be marshalled, in order
		// to fit the new data.
		//
		// If there is no Parent layer to marshal our new block's
		// reference-key pair into, create the above layer.
		if a.Parent == nil {
			var err error
			a.Parent, err = newAccumulator(a.W, a.Size, a.Secret, a.Level+1, nil)
			if err != nil {
				return err
			}
			a.ParentMarshal = recurMarshalBlocks(a.W, a.Secret, a.Parent.RecurAccumulate)
		}
		// Accumulate current references to parent
		err := a.ParentMarshal(a.RefKeyPairs)
		if err != nil {
			return err
		}
		// Have this accumulate a new sibling block.
		a.reset()
	}
	// Add the reference-key pair to the buffer, ensuring it respects the
	// expected bounds.
	a.add(ref, key)
	if a.N > int(a.Size) {
		return errors.New("adding reference-key exceeds block size")
	}
	return nil
}

// Flush forces the conversion of existing buffers into blocks, returning the
// root reference of the largest level singleton block.
func (a *accumulator) Flush() (root Ref, err error) {
	if a.Parent == nil {
		// Root accumulator case -- flush "this"
		// Special case: only 1 block reference. In this case, emit that
		// reference-key pair as the root one.
		if a.N == RefSize+KeySize {
			root.Level = a.Level - 1
			root.BlockSize = a.Size
			copy(root.Ref[:], a.RefKeyPairs[:RefSize])
			copy(root.Key[:], a.RefKeyPairs[RefSize:RefSize+KeySize])
			return
		}
		// Root accumulator needs to flush multiple references to one
		// new root block at this level.
		root.Level = a.Level
		root.BlockSize = a.Size
		cls := func(ref [RefSize]byte, key [KeySize]byte) error {
			copy(root.Ref[:], ref[:])
			copy(root.Key[:], key[:])
			return nil
		}
		a.ParentMarshal = recurMarshalBlocks(a.W, a.Secret, cls)
		err = a.ParentMarshal(a.RefKeyPairs)
		return
	} else {
		// Interior node case.
		//
		// Assume the buffer is never empty -- flush it to a new block
		// for the parent to then handle as a final reference-key pair.
		err = a.ParentMarshal(a.RefKeyPairs)
		if err != nil {
			return
		}
		return a.Parent.Flush()
	}
}

// recurMarshalBlocks is a closure that allows calling the same accumFn for
// multiple invocations, and emitting the block once it has been marshalled.
// This allows a streaming emission of the blocks.
func recurMarshalBlocks(w WriteFunc, secret []byte, accFn accumFn) marshalFn {
	return func(ublock ubytes) error {
		eblock, ref, readKey, err := marshalBlock(ublock, secret)
		if err != nil {
			return err
		}
		err = w(eblock, ref, readKey)
		if err != nil {
			return err
		}
		return accFn(ref, readKey)
	}
}

// marshalBlock is the actual instruction set to marshal a chunk of
// already-properly-sized bytes into a data block, with the given secret.
//
// The secret is allowed to be nil.
func marshalBlock(ublock ubytes, secret []byte) (eblock ebytes, ref [RefSize]byte, readKey [KeySize]byte, err error) {
	// Get Read Key
	readKey, err = toReadKey(ublock, secret)
	if err != nil {
		return
	}
	// Encrypt
	eblock, err = encrypt(ublock, readKey)
	if err != nil {
		return
	}
	// Get Reference
	ref = toRef(eblock)
	return
}

// padContentBlock pads the content to the nearest specified size.
//
// From 0.2 documentation:
//
// Input content is split into blocks of size at most block size such that only
// the last content block may be smaller than block size.
//
// The last content block is always padded according to the padding algorithm to
// block size. If the size of the padded last block is larger than block size it
// is split into content blocks of block size.
//
// If the length of the last content block is exactly block size, then padding
// will result in a padded block that is double the block size and must be
// split.
func padContentBlock(block ubytes, size BlockSize) ubytes {
	n := int(size) - len(block)%int(size)
	if n == 0 {
		n = int(size)
	}
	p := make([]byte, n) // TODO: Remove this allocation
	pad(p)
	return append(block, p...)
}

// toReadKey computes a read symmetric key with an optional secret, which may be
// nil.
//
// From 0.2 documentation:
//
// 1.
// Compute the hash of the unencrypted block. If a convergence secret is used
// the convergence secret MUST be used as key of the hash function. The output
// of the hash is the key.
func toReadKey(block ubytes, secret []byte) (rk [KeySize]byte, err error) {
	var h hash.Hash
	h, err = newCryptoHash(secret)
	if err != nil {
		return
	}
	var n int
	n, err = h.Write(block)
	if err != nil {
		return
	} else if n != len(block) {
		err = errors.New("could not write all content bytes to hash")
		return
	}
	key := h.Sum(nil)
	if len(key) != KeySize {
		err = errors.New("hash size is not equal to expected key size")
		return
	}
	copy(rk[:], key[:KeySize])
	return
}

// encrypt implements the encryption algorithm for a large chunk of plaintext.
//
// From 0.2 documentation:
//
// 2.
// Encrypt the block using the symmetric key cipher with the key.
func encrypt(block ubytes, key [KeySize]byte) (ebytes, error) {
	c, err := newSymmKeyCipher(key)
	if err != nil {
		return nil, err
	}
	// Encrypt in-place
	c.XORKeyStream(block[:], block)
	return ebytes(block), nil
}

// toRef determines the block reference for a block
//
// From 0.2 documentation:
//
// 3.
// The hash of the encrypted block is used as reference to the encrypted block.
func toRef(b ebytes) [RefSize]byte {
	return newRefHash(b)
}

/* Specific crypto & implementation dependencies. */

func newCryptoHash(key []byte) (hash.Hash, error) {
	return blake2b.New256(key)
}

func newRefHash(block []byte) [RefSize]byte {
	return blake2b.Sum256(block)
}

func newSymmKeyCipher(key [KeySize]byte) (cipher.Stream, error) {
	zNonce := make([]byte, chacha20.NonceSize) // TODO: Remove this allocation
	return chacha20.NewUnauthenticatedCipher(key[:], zNonce)
}

func pad(b []byte) {
	// ISO/IEC 7816-4
	if len(b) > 0 {
		b[0] = 0x80
	}
	for i := 1; i < len(b); i++ {
		b[i] = 0
	}
}

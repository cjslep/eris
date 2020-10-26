package eris

import (
	"crypto/cipher"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Kibi, base 2, definition
	kb = 1024
	mb = kb * 1024
	gb = mb * 1024
)

const (
	RefSize        = 32
	blockSize      = 1 * kb
	largeBlockSize = 32 * kb
)

// ebytes is an encrypted set of bytes
type ebytes []byte

// ubytes is an unencrypted set of bytes
type ubytes []byte

func EncodeV2(w writeFn, r io.Reader, secret []byte) error {
	// TODO: determine size
	size := largeBlockSize
	mFn, fFn := newMarshaller(w, secret, size)
	buf := make([]byte, size)
	for {
		n, err := io.ReadFull(r, buf)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			// Error reading.
			return err
		} else if n == 0 && err == io.EOF || // Do special closing padding block, then terminate; or...
			err == io.ErrUnexpectedEOF { // ...pad current block, then terminate.
			buf = padContentBlock(buf, size)
			fFn, err = mFn(buf)
			if err != nil {
				return err
			}
			return fFn()
		} else {
			// Process block normally.
			fFn, err = mFn(buf)
			if err != nil {
				return err
			}
		}
	}
}

// TL;DR: Strategy is to build the tree up recursively, growing in log-space
// memory requirements during single pass encoding.
func newMarshaller(w writeFn, secret []byte, size int) (marshalFn, flushFn) {
	acc, fl := recurAccumulateBlocks(w, secret, size, nil, nil)
	m := recurMarshalBlocks(w, secret, acc)
	return m, fl
}

type accumFn func(rkPair []byte) (accumFn, flushFn, error)
type marshalFn func(ublock ubytes) (flushFn, error)
type flushFn func() error
type writeFn func(eblock ebytes, ref [RefSize]byte, readkey []byte) error

func recurAccumulateBlocks(w writeFn, secret []byte, size int, parent marshalFn, parentFlush flushFn) (this accumFn, fl flushFn) {
	rkPairs := make([]byte, size)
	n := 0
	// Here be dragons and dark magick
	this = func(rkPair []byte) (accumFn, flushFn, error) {
		copy(rkPairs[n:], rkPair[:])
		n += len(rkPair)
		if n > size {
			return nil, nil, errors.New("invalid reference-key block size")
		} else if n == size {
			if parent == nil {
				var parentAcc accumFn
				parentAcc, parentFlush = recurAccumulateBlocks(w, secret, size, nil, nil)
				parent = recurMarshalBlocks(w, secret, parentAcc)
			}
			var err error
			parentFlush, err = parent(rkPairs)
			if err != nil {
				return nil, nil, err
			}
			a, f := recurAccumulateBlocks(w, secret, size, parent, parentFlush)
			return a, f, nil
		} else {
			return this, fl, nil
		}
	}
	fl = func() error {
		if n == 0 {
			return nil
		}
		if parent == nil || parentFlush == nil {
			return nil
		}
		var err error
		parentFlush, err = parent(rkPairs)
		if err != nil {
			return err
		}
		return parentFlush()
	}
	return
}

func recurMarshalBlocks(w writeFn, secret []byte, accFn accumFn) marshalFn {
	return func(ublock ubytes) (flushFn, error) {
		eblock, ref, readKey, err := marshalBlock(ublock, secret)
		if err != nil {
			return nil, err
		}
		err = w(eblock, ref, readKey)
		if err != nil {
			return nil, err
		}
		rkPair := append(ref[:], readKey...)
		var fl flushFn
		accFn, fl, err = accFn(rkPair)
		return fl, err
	}
}

func marshalBlock(ublock ubytes, secret []byte) (eblock ebytes, ref [RefSize]byte, readKey []byte, err error) {
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
func padContentBlock(block ubytes, size int) ubytes {
	n := size - len(block)%size
	if n == 0 {
		n = size
	}
	p := make([]byte, n)
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
func toReadKey(block ubytes, secret []byte) ([]byte, error) {
	h, err := newCryptoHash(secret)
	if err != nil {
		return nil, err
	}
	n, err := h.Write(block)
	if err != nil {
		return nil, err
	} else if n != len(block) {
		return nil, errors.New("could not write all content bytes to hash")
	}
	key := h.Sum(nil)
	return key, nil
}

// encrypt implements the encryption algorithm for a large chunk of plaintext.
//
// From 0.2 documentation:
//
// 2.
// Encrypt the block using the symmetric key cipher with the key.
func encrypt(block ubytes, key []byte) (ebytes, error) {
	c, err := newSymmKeyCipher(key)
	if err != nil {
		return nil, err
	}
	// TODO: Nonce all-zero?
	nonce := make([]byte, c.NonceSize())
	// Encrypt in-place
	return c.Seal(block[:0], nonce, block, nil), nil
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

func newBlockSizeReader(r io.Reader) io.Reader {
	return io.LimitReader(r, blockSize)
}

func newCryptoHash(key []byte) (hash.Hash, error) {
	return blake2b.New256(key)
}

func newRefHash(block []byte) [RefSize]byte {
	return blake2b.Sum256(block)
}

func newSymmKeyCipher(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
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

func missingRefs(n int) []byte {
	// All-zeroes
	return make([]byte, n)
}

package eris

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"encoding/base32"
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Spec says kilo but it is kibi
	kb = 1024
	mb = kb * 1024
	gb = mb * 1024
)

const (
	xPath         = 255
	RefSize       = 32
	refsPerNode   = 128
	nonceByteSize = 12
	blockSize     = 4 * kb
	chunkSize     = 256 * gb
)

type Block struct {
	Ref [RefSize]byte
	B   []byte
}

func (b Block) String() string {
	// TODO: Base32 Hex or Std encoding?
	return base32.StdEncoding.EncodeToString(b.Ref[:])
}

type Root struct {
	Ref [RefSize]byte
	Level byte
	ReadKey []byte
}

func (r Root) String() string {
	// TODO: Base32 Hex or Std encoding?
	b := make([]byte, 0, 67)
	b = append(b, 0) // version
	b = append(b, 0) // read cap
	b = append(b, r.Level)
	b = append(b, r.Ref[:]...)
	b = append(b, r.ReadKey...)
	return "urn:eris:" + base32.StdEncoding.EncodeToString(b)
}

func Encode(r io.Reader, secret []byte) (root Root, l []Block, err error) {
	chr := newChunkReader(r)

	// TODO: Support streaming due to open questions, for now let's just max out at 1gb.
	b := make([]byte, 1*gb)
	var n int
	var readErr error
	n, readErr = chr.Read(b)
	b = b[:n]

	// TODO: How does determining the read key work with chunking a stream > 256GB?
	var key []byte
	key, err = toReadKey(b, secret)
	if err != nil {
		return
	}

	l, err = encodeChunkToDataBlocks(b, key, chunkNonce())
	if err != nil {
		return
	} else if readErr != io.EOF {
		err = errors.New("unsupported: encoding larger than 1 GB")
	}

	var bl []Block
	var level byte
	bl, level, err = encodeTree(l, key, firstNonce(), 1)
	l = append(l, bl...)

	root = Root {
		Ref: l[len(l)-1].Ref,
		Level: level,
		ReadKey: key,
	}
	return
}

func encodeTree(l []Block, key []byte, nonce [nonceByteSize]byte, level byte) (r []Block, outLevel byte, err error) {
	// Base case: previous level is root
	if len(l) == 1 {
		return nil, level-1, nil
	}

	// Build the current Merkle tree level out
	for len(l) > 0 {
		plain := make([]byte, 0, blockSize)
		var i int
		for i = 0; i < len(l) && i < refsPerNode; i++ {
			plain = append(plain, l[i].Ref[:]...)
		}
		l = l[i:]
		if len(plain) < blockSize {
			plain = append(plain, missingRefs(blockSize-len(plain))...)
		}
		var enc []byte
		enc, err = encrypt(plain, /* TODO: Was verify key? */ key, nonce)
		if err != nil {
			return
		}
		r = append(r, toBlock(enc))
		incrementNonceInPlace(nonce)
	}

	// Otherwise, recur upwards in the Merkle tree.
	var above []Block
	zerothNextXPathNonceInPlace(nonce)
	above, outLevel, err = encodeTree(r, key, nonce, level+1)
	r = append(r, above...)
	return
}

func encodeChunkToDataBlocks(plain, key []byte, cNonce [nonceByteSize]byte) (l []Block, err error) {
	// TODO: Since this is encrypted before enforcing block-chunking, cannot use same logic as merkle tree?
	plain = padContent(plain)
	var enc []byte
	enc, err = encrypt(plain, key, cNonce)
	if err != nil {
		return
	}

	l = make([]Block, 0, len(plain)/blockSize)
	r := bytes.NewReader(enc)
	for r.Len() > 0 {
		br := newBlockSizeReader(r)
		b := make([]byte, blockSize)
		n, readErr := br.Read(b)

		l = append(l, toBlock(b[:n]))
		if readErr != io.EOF {
			err = readErr
			return
		}
	}
	return
}

func toBlock(content []byte) Block {
	return Block{
		Ref: toRef(content),
		B:   content,
	}
}

// padContent pads the content to the nearest blockSize.
//
// From the documentation:
//
// Content is first padded (see Cryptographic Primitives) to a multiple of
// 4kB.
func padContent(content []byte) []byte {
	p := make([]byte, blockSize - len(content)%blockSize)
	pad(p)
	return append(content, p...)
}

// toReadKey computes a read symmetric key with an optional secret, which may be
// nil.
//
// From the documentation:
//
// The key used to encrypt the content. The read key is BLAKE2b(content). If a
// convergence secret is given the read key is BLAKE2b(content,
// key=covergence-secret) (using keyed hashing).
func toReadKey(content, secret []byte) ([]byte, error) {
	content = padContent(content)
	h, err := newCryptoHash(secret)
	if err != nil {
		return nil, err
	}
	n, err := h.Write(content)
	if err != nil {
		return nil, err
	} else if n != len(content) {
		return nil, errors.New("could not write all content bytes to hash")
	}
	key := h.Sum(nil)
	return key, nil
}

// encrypt implements the encryption algorithm for a large chunk of plaintext.
//
// From the documentation:
//
// Step 2:
// Content is then encoded with the symmetric key cypher using the read key and
// nonce set to 0. If content is larger than 256 GB use nonce 0 for first 256 GB
// and increment nonce for successive chunks of 256 GB.
func encrypt(chunk, key []byte, nonce [nonceByteSize]byte) ([]byte, error) {
	c, err := newSymmKeyCipher(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != c.NonceSize() {
		return nil, errors.New("nonce is of incorrect size")
	}
	// Encrypt in-place
	return c.Seal(chunk[:0], nonce[:], chunk, nil), nil
}

// toRef determines the block reference for a block
//
// From the documentation:
//
// Step 3:
// Encrypted content is split into blocks of size 4kB. The blocks holding
// encrypted content are called data blocks.
func toRef(block []byte) [RefSize]byte {
	return newRefHash(block)
}

/* Nonces for chunks */

func chunkNonce() (b [nonceByteSize]byte) {
	// All-zeroes
	return
}

/* Nonce-management for internal nodes */

func firstNonce() (b [nonceByteSize]byte) {
	// All-zeroes
	return
}

func zerothNextXPathNonceInPlace(b [nonceByteSize]byte) error {
	if b[1] == xPath {
		return errors.New("attempting to encode content too large: nonce path limit reached")
	}
	b[0] = 0
	for i := 1; i < nonceByteSize-1; i++ {
		if b[i+1] == xPath {
			b[i] = xPath
		} else {
			b[i] = 0
		}
	}
	b[nonceByteSize-1] = xPath
	return nil
}

func incrementNonceInPlace(b [nonceByteSize]byte) error {
	var i int
	for i = nonceByteSize - 1; i >= 0; i-- {
		if b[i] != xPath {
			break
		}
	}
	if i < 0 {
		return errors.New("attempting to encode content too large: nonce path limit reached")
	}
	b[i]++ // Increment current
	// Enforce base-128 encoding of position
	i-- // Start examining second-128ths place
	for i >= 0 && b[i+1] >= 128 {
		b[i+1] = 0
		b[i]++
		i--
	}
	if i < 0 && b[0] >= 128 {
		return errors.New("attempting to encode content too large: nonce base-128 encoding limit reached")
	}
	return nil
}

/* Specific crypto & implementation dependencies. */

func newChunkReader(r io.Reader) io.Reader {
	return io.LimitReader(r, chunkSize)
}

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

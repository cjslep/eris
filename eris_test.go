package eris

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/go-test/deep"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
)

var _ Storage = new(TestVector)

type TestVector struct {
	Id                int                    `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	Content           string                 `json:"content"`
	ConvergenceSecret string                 `json:"convergence-secret"`
	BlockSize         BlockSize              `json:"block-size"`
	ReadCapability    TestReadCap            `json:"read-capability"`
	URN               string                 `json:"urn"`
	Blocks            map[string]interface{} `json:"blocks"`
}

func (t TestVector) Get(ref [RefSize]byte) ([]byte, error) {
	sref := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(ref[:])
	v, ok := t.Blocks[sref]
	if !ok {
		return nil, fmt.Errorf("test vector %d does not have ref=%s", t.Id, sref)
	}
	sv := v.(string)
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(sv)
}

type TestReadCap struct {
	BlockSize BlockSize `json:"block-size"`
	Level     int       `json:"level"`
	RootRef   string    `json:"root-reference"`
	RootKey   string    `json:"root-key"`
}

func (t TestReadCap) AsRef() (Ref, error) {
	r := Ref{
		BlockSize: t.BlockSize,
		Level:     t.Level,
	}
	rbuf, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(t.RootRef)
	if err != nil {
		return r, err
	}
	kbuf, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(t.RootKey)
	if err != nil {
		return r, err
	}
	copy(r.Ref[:], rbuf)
	copy(r.Key[:], kbuf)
	return r, nil
}

var files []string = []string{
	"test-vectors_eris-test-vector-00.json",
	"test-vectors_eris-test-vector-01.json",
	"test-vectors_eris-test-vector-02.json",
	"test-vectors_eris-test-vector-03.json",
	"test-vectors_eris-test-vector-04.json",
	"test-vectors_eris-test-vector-05.json",
	"test-vectors_eris-test-vector-06.json",
	"test-vectors_eris-test-vector-07.json",
	"test-vectors_eris-test-vector-08.json",
	"test-vectors_eris-test-vector-09.json",
	"test-vectors_eris-test-vector-10.json",
	"test-vectors_eris-test-vector-11.json",
	"test-vectors_eris-test-vector-12.json",
}

type BlockAccumulator struct {
	N int
	B map[string]string
	K map[string]string
}

func (b *BlockAccumulator) Accumulate(eblock ebytes, ref [RefSize]byte, readKey [KeySize]byte) error {
	if b.N == 0 {
		b.B = make(map[string]string)
		b.K = make(map[string]string)
	}
	r := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(ref[:])
	b.B[r] = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(eblock)
	b.K[r] = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(readKey[:])
	b.N++
	return nil
}

func (b BlockAccumulator) Diff(blocks map[string]interface{}) error {
	var err BlockDiffError
	for k, v := range b.B {
		err.NHave++
		bv, ok := blocks[k]
		if !ok {
			err.Added = append(err.Added, k)
			continue
		}
		bs := bv.(string)
		if bs != v {
			err.Mismatch = append(err.Mismatch, k)
			continue
		}
	}
	for k, v := range blocks {
		err.NWant++
		bv, ok := b.B[k]
		if !ok {
			err.Missing = append(err.Missing, k)
			continue
		}
		s := v.(string)
		if s != bv {
			err.Mismatch = append(err.Mismatch, k)
			continue
		}
	}
	return err.GetOrNil()
}

type BlockDiffError struct {
	NHave    int
	NWant    int
	Added    []string
	Missing  []string
	Mismatch []string
}

func (b BlockDiffError) Error() string {
	var bs strings.Builder
	fmt.Fprintf(&bs, "block diff error; have %d, want %d:\n", b.NHave, b.NWant)
	for _, a := range b.Added {
		fmt.Fprintf(&bs, "\tunwanted ref: %s\n", a)
	}
	for _, m := range b.Missing {
		fmt.Fprintf(&bs, "\tmissing ref: %s\n", m)
	}
	for _, m := range b.Mismatch {
		fmt.Fprintf(&bs, "\tbad ref val: %s\n", m)
	}
	return bs.String()
}

func (b BlockDiffError) GetOrNil() error {
	if len(b.Added) == 0 && len(b.Missing) == 0 && len(b.Mismatch) == 0 {
		return nil
	}
	return b
}

func TestEncodeVectors(t *testing.T) {
	for _, file := range files {
		b, err := ioutil.ReadFile("./testdata/" + file)
		if err != nil {
			t.Errorf("error reading %s: %v", file, err)
			continue
		}
		var test TestVector
		err = json.Unmarshal(b, &test)
		if err != nil {
			t.Errorf("error unmarshalling %s: %v", file, err)
			continue
		}
		bcon, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(test.Content)
		if err != nil {
			t.Errorf("error decoding content %s: %v", file, err)
			continue
		}
		bconv, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(test.ConvergenceSecret)
		if err != nil {
			t.Errorf("error decoding convergence secret %s: %v", file, err)
			continue
		}
		t.Run(test.Name, func(t *testing.T) {
			var b BlockAccumulator
			r := bytes.NewReader(bcon)
			var err error
			var ref Ref
			if test.BlockSize == Size1KiB {
				ref, err = Encode1KiB((&b).Accumulate, r, bconv)
			} else if test.BlockSize == Size32KiB {
				ref, err = Encode32KiB((&b).Accumulate, r, bconv)
			} else {
				err = fmt.Errorf("unsupported test vector block size: %d", test.BlockSize)
			}
			// Check the blocks
			if err != nil {
				t.Errorf("got %s, want %v", err, nil)
			}
			if err = b.Diff(test.Blocks); err != nil {
				t.Errorf("%v", err)
			}
			// Check the URN
			urn, err := ref.URN()
			if urn != test.URN {
				t.Errorf("got %s, want %s", urn, test.URN)
			}
			// Check the root-reference details (double-checks URN)
			if ref.BlockSize != test.ReadCapability.BlockSize {
				t.Errorf("got %d, want %d", ref.BlockSize, test.ReadCapability.BlockSize)
			}
			if ref.Level != test.ReadCapability.Level {
				t.Errorf("got %d, want %d", ref.Level, test.ReadCapability.Level)
			}
			if s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(ref.Ref[:]); s != test.ReadCapability.RootRef {
				t.Errorf("got %s, want %s", s, test.ReadCapability.RootRef)
			}
			if s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(ref.Key[:]); s != test.ReadCapability.RootKey {
				t.Errorf("got %s, want %s", s, test.ReadCapability.RootKey)
			}
			t.Logf("ref: %v", ref)
			t.Logf("urn: %s", urn)
		})
	}
}

func TestDecodeVectors(t *testing.T) {
	for _, file := range files {
		b, err := ioutil.ReadFile("./testdata/" + file)
		if err != nil {
			t.Errorf("error reading %s: %v", file, err)
			continue
		}
		var test TestVector
		err = json.Unmarshal(b, &test)
		if err != nil {
			t.Errorf("error unmarshalling %s: %v", file, err)
			continue
		}
		bcon, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(test.Content)
		if err != nil {
			t.Errorf("error decoding content %s: %v", file, err)
			continue
		}
		rootRef, err := test.ReadCapability.AsRef()
		if err != nil {
			t.Errorf("error decoding read capability as ref %s: %v", file, err)
			continue
		}
		t.Run(test.Name, func(t *testing.T) {
			var buf bytes.Buffer
			err := Decode(&test, &buf, rootRef)
			if err != nil {
				t.Errorf("got %s, want %v", err, nil)
			}
			bb := buf.Bytes()
			diffs := deep.Equal(bb, bcon)
			if len(diffs) > 0 {
				t.Errorf("got diffs: %v", diffs)
			}
		})
	}
}

func getStreamingGenerator(testName string, size BlockSize, l int) (ReaderFunc, error) {
	key := blake2b.Sum256([]byte(testName))
	zNonce := make([]byte, chacha20.NonceSize)
	s, err := chacha20.NewUnauthenticatedCipher(key[:], zNonce)
	zb := make([]byte, size)
	gen := 0
	return func(b []byte) (n int, err error) {
		if len(b) != len(zb) {
			return 0, fmt.Errorf("test streaming generator size mismatch: %d vs %d", len(b), len(zb))
		}
		n = l - gen
		if n > len(b) {
			n = len(b)
		}
		gen += n
		s.XORKeyStream(b, zb[:n])
		if n == 0 || gen == l {
			err = io.EOF
		}
		return
	}, err
}

var _ io.Reader = ReaderFunc(nil)

type ReaderFunc func(b []byte) (n int, err error)

func (r ReaderFunc) Read(b []byte) (n int, err error) {
	return r(b)
}


func TestStreamingEncode(t *testing.T) {
	tests := []struct {
		Name          string
		BlockSize     BlockSize
		ContentLength int
		ExpectedURN   string
	}{
		/* TODO: Figure out why these are incorrect
		{
			Name:          "100MiB (block size 1KiB)",
			BlockSize:     Size1KiB,
			ContentLength: 100 * mb,
			ExpectedURN:   "urn:erisx2:AACXPZNDNXFLO4IOMF6VIV2ZETGUJEUU7GN4AHPWNKEN6KJMCNP6YNUMVW2SCGZUJ4L3FHIXVECRZQ3QSBOTYPGXHN2WRBMB27NXDTAP24",
		},
		{
			Name:          "1GiB (block size 32KiB)",
			BlockSize:     Size32KiB,
			ContentLength: 1 * gb,
			ExpectedURN:   "urn:erisx2:AEBFG37LU5BM5N3LXNPNMGAOQPZ5QTJAV22XEMX3EMSAMTP7EWOSD2I7AGEEQCTEKDQX7WCKGM6KQ5ALY5XJC4LMOYQPB2ZAFTBNDB6FAA",
		},
		*/
		// This test times out go's 10 minute built-in test timer.
		/*		{
					Name:          "256GiB (block size 32KiB)",
					BlockSize:     Size32KiB,
					ContentLength: 256 * gb,
					ExpectedURN:   "urn:erisx2:AEBZHI55XJYINGLXWKJKZHBIXN6RSNDU233CY3ELFSTQNSVITBSVXGVGBKBCS4P4M5VSAUOZSMVAEC2VDFQTI5SEYVX4DN53FTJENWX4KU",
				},
		*/
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			nBlocks := 0
			writeFunc := func(eblock ebytes, ref [RefSize]byte, readkey [KeySize]byte) error {
				nBlocks++
				return nil
			}
			gen, err := getStreamingGenerator(test.Name, test.BlockSize, test.ContentLength)
			if err != nil {
				t.Errorf("error creating generator: %v", err)
				return
			}

			var ref Ref
			if test.BlockSize == Size1KiB {
				ref, err = Encode1KiB(writeFunc, gen, nil)
			} else if test.BlockSize == Size32KiB {
				ref, err = Encode32KiB(writeFunc, gen, nil)
			} else {
				err = fmt.Errorf("unsupported test vector block size: %d", test.BlockSize)
			}
			if err != nil {
				t.Errorf("got %s, want %v", err, nil)
			}

			t.Logf("number of blocks: %d", nBlocks)
			// Check the URN
			urn, err := ref.URN()
			if urn != test.ExpectedURN {
				t.Errorf("got %s, want %s", urn, test.ExpectedURN)
			}
		})
	}
}

func BenchmarkStreamingEncode1KiB(b *testing.B) {
	b.Logf("n=%d", b.N)
	nBlocks := 0
	writeFunc := func(eblock ebytes, ref [RefSize]byte, readkey [KeySize]byte) error {
		nBlocks++
		return nil
	}
	name := fmt.Sprintf("test-%d", b.N)
	gen, err := getStreamingGenerator(name, Size1KiB, b.N * int(Size1KiB))
	if err != nil {
		b.Errorf("error creating generator: %v", err)
		return
	}

	b.ResetTimer()
	ref, err := Encode1KiB(writeFunc, gen, nil)
	if err != nil {
		b.Errorf("got %s, want %v", err, nil)
	}
	urn, err := ref.URN()
	if err != nil {
		b.Errorf("got %s, want %v", err, nil)
	}
	b.Logf("ref=%s", urn)
	b.Logf("number of blocks: %d", nBlocks)
}

func BenchmarkStreamingEncode32KiB(b *testing.B) {
	b.Logf("n=%d", b.N)
	nBlocks := 0
	writeFunc := func(eblock ebytes, ref [RefSize]byte, readkey [KeySize]byte) error {
		nBlocks++
		return nil
	}
	name := fmt.Sprintf("test-%d", b.N)
	gen, err := getStreamingGenerator(name, Size32KiB, b.N * int(Size1KiB))
	if err != nil {
		b.Errorf("error creating generator: %v", err)
		return
	}

	b.ResetTimer()
	ref, err := Encode32KiB(writeFunc, gen, nil)
	if err != nil {
		b.Errorf("got %s, want %v", err, nil)
	}
	urn, err := ref.URN()
	if err != nil {
		b.Errorf("got %s, want %v", err, nil)
	}
	b.Logf("ref=%s", urn)
	b.Logf("number of blocks: %d", nBlocks)
}

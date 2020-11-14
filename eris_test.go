package eris

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
)

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

type TestReadCap struct {
	BlockSize BlockSize `json:"block-size"`
	Level     int       `json:"level"`
	RootRef   string    `json:"root-reference"`
	RootKey   string    `json:"root-key"`
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

package eris

import (
	"bytes"
	"encoding/base32"
	"fmt"
	"math/rand"
	"testing"
)

func testWriteFn() func(eblock ebytes, ref [RefSize]byte, readKey []byte) error {
	n := 0
	return func(eblock ebytes, ref [RefSize]byte, readKey []byte) error {
		b := make([]byte, 0, 66)
		b = append(b, 0) // version
		b = append(b, 0) // root reference, made up
		b = append(b, ref[:]...)
		b = append(b, readKey...)
		fmt.Printf("%d block: urn:eris:%s\n", n, base32.StdEncoding.EncodeToString(b))
		fmt.Println(" ref=", base32.StdEncoding.EncodeToString(ref[:]))
		fmt.Println(" key=", base32.StdEncoding.EncodeToString(readKey))
		n++
		return nil
	}
}

func garbo(n int) string {
	s := make([]byte, n)
	rand.Read(s)
	return string(s)
}

func TestEncodeV2(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{
			name: "spec",
			in:   "Hail ERIS!",
		},
		{
			name: "padding edge case",
			in:   garbo(largeBlockSize),
		},
		{
			name: "1 larger than block size",
			in:   garbo(largeBlockSize + 1),
		},
		{
			name: "1 larger than 1 inner node size",
			in:   garbo(largeBlockSize*512 + 1),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fmt.Println(test.name)
			r := bytes.NewReader([]byte(test.in))
			err := EncodeV2(testWriteFn(), r, nil)
			if err != nil {
				t.Errorf("got %s, want %v", err, nil)
			}
			fmt.Println()
		})
	}
}

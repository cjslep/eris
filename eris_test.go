package eris

import (
	"bytes"
	"testing"
	"fmt"
)

func TestEncode(t *testing.T) {
	tests := []struct{
		name string
		in string
	}{
		{
			name: "spec",
			in: "Hail ERIS!",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := bytes.NewReader([]byte(test.in))
			root, l, err := Encode(r, nil)
			if err != nil {
				t.Errorf("got %s, want %v", err, nil)
			}
			fmt.Println(root)
			fmt.Println(l)
		})
	}
}

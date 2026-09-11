package paste

import (
	"bytes"
	"errors"
	"testing"
)

func TestCanonicalize_PrependsBOMExactlyOnce(t *testing.T) {
	want := append(append([]byte(nil), BOM...), []byte("hello")...)

	withoutBOM, err := Canonicalize("hello", int64(len(want)))
	if err != nil {
		t.Fatalf("without BOM: %v", err)
	}
	if !bytes.Equal(withoutBOM, want) {
		t.Fatalf("without BOM: got %x, want %x", withoutBOM, want)
	}

	withBOM, err := Canonicalize(string(want), int64(len(want)))
	if err != nil {
		t.Fatalf("with BOM: %v", err)
	}
	if !bytes.Equal(withBOM, want) {
		t.Fatalf("with BOM: got %x, want %x", withBOM, want)
	}
}

func TestCanonicalize_PreservesContentBytes(t *testing.T) {
	content := "first\r\nsecond\n\tภาษาไทย 😀"
	want := append(append([]byte(nil), BOM...), []byte(content)...)

	got, err := Canonicalize(content, int64(len(want)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestCanonicalize_RejectsInvalidUTF8(t *testing.T) {
	_, err := Canonicalize(string([]byte{0xff, 0xfe}), 100)
	if !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("got %v, want ErrInvalidUTF8", err)
	}
}

func TestCanonicalize_SizeLimitIncludesBOM(t *testing.T) {
	if _, err := Canonicalize("1234567", 10); err != nil {
		t.Fatalf("exactly at limit: %v", err)
	}

	_, err := Canonicalize("12345678", 10)
	var tooLarge *ErrTooLarge
	if !errors.As(err, &tooLarge) {
		t.Fatalf("got %v, want *ErrTooLarge", err)
	}
	if tooLarge.Limit != 10 || tooLarge.Actual != 11 {
		t.Fatalf("got limit=%d actual=%d, want limit=10 actual=11", tooLarge.Limit, tooLarge.Actual)
	}
}

func TestCanonicalize_EmptyContentIsBOM(t *testing.T) {
	got, err := Canonicalize("", 3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, BOM) {
		t.Fatalf("got %x, want %x", got, BOM)
	}
}

func TestBOMHelpers(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		has  bool
		want []byte
	}{
		{name: "nil", in: nil, want: nil},
		{name: "empty", in: []byte{}, want: []byte{}},
		{name: "one byte", in: []byte{0xef}, want: []byte{0xef}},
		{name: "two bytes", in: []byte{0xef, 0xbb}, want: []byte{0xef, 0xbb}},
		{name: "different three bytes", in: []byte{0xef, 0xbb, 0x00}, want: []byte{0xef, 0xbb, 0x00}},
		{name: "BOM only", in: append([]byte(nil), BOM...), has: true, want: []byte{}},
		{name: "BOM and content", in: append(append([]byte(nil), BOM...), 'x'), has: true, want: []byte{'x'}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasBOM(tc.in); got != tc.has {
				t.Errorf("HasBOM() = %v, want %v", got, tc.has)
			}
			if got := StripBOM(tc.in); !bytes.Equal(got, tc.want) {
				t.Errorf("StripBOM() = %x, want %x", got, tc.want)
			}
		})
	}
}

func TestHashHex_PinnedCanonicalHello(t *testing.T) {
	canonical := append(append([]byte(nil), BOM...), []byte("hello")...)
	const want = "7489ebbcc2a00056ddaaaac190bce473e5c03696ea1bd8ed83cf59a174283862"
	if got := HashHex(canonical); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

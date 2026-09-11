package config

import (
	"errors"
	"testing"
)

func TestParseSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		err  bool
	}{
		{"1024KB", 1048576, false},
		{"1024 kb", 1048576, false},
		{"256KB", 262144, false},
		{"1MB", 1048576, false},
		{"16MB", 16777216, false},
		{"512B", 512, false},
		{"0", 0, true},
		{"0KB", 0, true},
		{"17MB", 0, true},  // above hard cap
		{"1GB", 0, true},   // unit not allowed
		{"1.5MB", 0, true}, // no fractions
		{"abc", 0, true},
		{"", 0, true},
		{"-1KB", 0, true},
	}
	for _, c := range cases {
		got, err := ParseSize(c.in)
		if c.err {
			if err == nil || !errors.Is(err, ErrBadSize) {
				t.Errorf("ParseSize(%q) err = %v, want ErrBadSize", c.in, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", c.in, got, err, c.want)
		}
	}
}

func TestFormatSize(t *testing.T) {
	cases := map[int64]string{
		0:       "0 B",
		512:     "512 B",
		1024:    "1 KB",
		12595:   "12.3 KB",
		1048576: "1 MB",
		1572864: "1.5 MB",
	}
	for in, want := range cases {
		if got := FormatSize(in); got != want {
			t.Errorf("FormatSize(%d) = %q, want %q", in, got, want)
		}
	}
}

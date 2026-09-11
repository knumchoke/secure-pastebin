package config

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ErrBadSize is returned for any unparsable or out-of-range size string.
var ErrBadSize = errors.New("config: invalid size (expected e.g. 256KB, 1024KB, 1MB; binary units; max 16MB)")

// MaxPasteSizeHardCap is the absolute ceiling for PASTE_MAX_SIZE (spec §12).
const MaxPasteSizeHardCap int64 = 16 << 20

var sizeRe = regexp.MustCompile(`^(\d+)\s*(B|KB|MB)$`)

// ParseSize parses "<int><unit>" with binary units (KB = 1024 B).
// Zero, fractions, negative values and units other than B/KB/MB are rejected.
func ParseSize(s string) (int64, error) {
	m := sizeRe.FindStringSubmatch(strings.ToUpper(strings.TrimSpace(s)))
	if m == nil {
		return 0, ErrBadSize
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, ErrBadSize
	}
	switch m[2] {
	case "KB":
		n <<= 10
	case "MB":
		n <<= 20
	}
	if n <= 0 || n > MaxPasteSizeHardCap {
		return 0, ErrBadSize
	}
	return n, nil
}

// FormatSize renders bytes with binary units and at most one decimal.
func FormatSize(n int64) string {
	switch {
	case n >= 1<<20:
		return trimFloat(float64(n)/(1<<20)) + " MB"
	case n >= 1<<10:
		return trimFloat(float64(n)/(1<<10)) + " KB"
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func trimFloat(f float64) string {
	s := strconv.FormatFloat(f, 'f', 1, 64)
	return strings.TrimSuffix(s, ".0")
}

// Package redact masks secret values in a stream, across write boundaries.
//
// Matching is exact (no heuristics); values are replaced longest-first with
// [redacted:NAME]. A tail of maxLen-1 bytes is held back so a value split
// across writes is still caught.
package redact

import (
	"io"
	"sort"
	"strings"
)

type pair struct {
	value string
	name  string
}

// Writer is an io.Writer that masks registered secret values.
type Writer struct {
	out   io.Writer
	pairs []pair
	buf   []byte
}

// New returns a redacting writer. secrets maps secret value → display name.
func New(out io.Writer, secrets map[string]string) *Writer {
	pairs := sortedPairs(secrets)
	return &Writer{out: out, pairs: pairs}
}

// String masks registered values in s (used for audit command lines).
func String(s string, secrets map[string]string) string {
	out, _ := replace(s, sortedPairs(secrets), true)
	return out
}

func sortedPairs(secrets map[string]string) []pair {
	pairs := make([]pair, 0, len(secrets))
	for v, name := range secrets {
		if v == "" {
			continue
		}
		pairs = append(pairs, pair{value: v, name: name})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if len(pairs[i].value) != len(pairs[j].value) {
			return len(pairs[i].value) > len(pairs[j].value)
		}
		return pairs[i].name < pairs[j].name
	})
	return pairs
}

func (w *Writer) Write(p []byte) (int, error) {
	if len(w.pairs) == 0 {
		return w.out.Write(p)
	}
	w.buf = append(w.buf, p...)

	out, consumed := replace(string(w.buf), w.pairs, false)
	if err := write(w.out, out); err != nil {
		return 0, err
	}
	w.buf = append(w.buf[:0], w.buf[consumed:]...)
	return len(p), nil
}

// Flush writes the remaining buffered bytes (masked).
func (w *Writer) Flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	out, _ := replace(string(w.buf), w.pairs, true)
	err := write(w.out, out)
	w.buf = nil
	return err
}

// Leftmost, longest match. Never rescan generated markers (short secrets could
// otherwise corrupt them). Only retain an actual partial prefix between writes.
func replace(input string, pairs []pair, final bool) (string, int) {
	var out strings.Builder
	i := 0
	for i < len(input) {
		rest := input[i:]
		matched := false
		for _, p := range pairs {
			if !final && len(rest) < len(p.value) && strings.HasPrefix(p.value, rest) {
				return out.String(), i
			}
			if strings.HasPrefix(rest, p.value) {
				out.WriteString("[redacted:" + p.name + "]")
				i += len(p.value)
				matched = true
				break
			}
		}
		if !matched {
			out.WriteByte(input[i])
			i++
		}
	}
	return out.String(), i
}

func write(out io.Writer, text string) error {
	if text == "" {
		return nil
	}
	n, err := io.WriteString(out, text)
	if err == nil && n != len(text) {
		return io.ErrShortWrite
	}
	return err
}

// Package redact masks secret values in a stream, across write boundaries.
//
// Matching is exact (no heuristics); values are replaced longest-first with
// [redacted:NAME]. A tail of maxLen-1 bytes is held back so a value split
// across writes is still caught.
package redact

import (
	"bytes"
	"io"
	"sort"
)

type pair struct {
	value string
	name  string
}

// Writer is an io.Writer that masks registered secret values.
type Writer struct {
	out    io.Writer
	pairs  []pair
	maxLen int
	buf    []byte
}

// New returns a redacting writer. secrets maps secret value → display name.
func New(out io.Writer, secrets map[string]string) *Writer {
	pairs := sortedPairs(secrets)
	maxLen := 0
	for _, p := range pairs {
		if len(p.value) > maxLen {
			maxLen = len(p.value)
		}
	}
	return &Writer{out: out, pairs: pairs, maxLen: maxLen}
}

// String masks registered values in s (used for audit command lines).
func String(s string, secrets map[string]string) string {
	return string(replaceAll([]byte(s), sortedPairs(secrets)))
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
	if w.maxLen == 0 {
		return w.out.Write(p)
	}
	w.buf = append(w.buf, p...)

	// Everything before safe is complete: no match starting there can extend
	// beyond the buffer.
	safe := len(w.buf) - (w.maxLen - 1)
	if safe <= 0 {
		return len(p), nil
	}

	emitEnd := safe
	lo := safe - w.maxLen + 1
	if lo < 0 {
		lo = 0
	}
	// Defer a match that would straddle the emit boundary.
	for _, pr := range w.pairs {
		val := []byte(pr.value)
		search := lo
		for search < safe {
			j := bytes.Index(w.buf[search:], val)
			if j < 0 {
				break
			}
			s := search + j
			if s >= safe {
				break
			}
			if s+len(val) > safe && s < emitEnd {
				emitEnd = s
			}
			search = s + 1
		}
	}

	if _, err := w.out.Write(replaceAll(w.buf[:emitEnd], w.pairs)); err != nil {
		return 0, err
	}
	w.buf = append(w.buf[:0], w.buf[emitEnd:]...)
	return len(p), nil
}

// Flush writes the remaining buffered bytes (masked).
func (w *Writer) Flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	_, err := w.out.Write(replaceAll(w.buf, w.pairs))
	w.buf = nil
	return err
}

func replaceAll(b []byte, pairs []pair) []byte {
	for _, p := range pairs {
		b = bytes.ReplaceAll(b, []byte(p.value), []byte("[redacted:"+p.name+"]"))
	}
	return b
}

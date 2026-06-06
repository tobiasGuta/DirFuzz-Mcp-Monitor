package engine

import (
	"bytes"
	"testing"
)

func TestSimhashBodyCorrectness(t *testing.T) {
	tests := []struct {
		body []byte
	}{
		{body: []byte("hello world this is a test")},
		{body: []byte("  leading   and   trailing   spaces  ")},
		{body: []byte("punctuation! testing, punctuation; here.")},
		{body: []byte("")},
		{body: []byte("singleword")},
		{body: []byte("!!! !!!")},
	}

	for _, tc := range tests {
		got := simhashBody(tc.body)
		expected := originalSimhashBody(tc.body)
		if got != expected {
			t.Errorf("for body %q: expected %x, got %x", string(tc.body), expected, got)
		}
	}
}

// originalSimhashBody is the old allocating implementation kept for correctness testing.
func originalSimhashBody(body []byte) uint64 {
	text := string(body)
	var tokens []string
	var current bytes.Buffer
	for _, r := range text {
		if runeIsSpaceOrPunct(r) {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		} else {
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	if len(tokens) == 0 {
		return 0
	}

	var vector [64]int
	for _, token := range tokens {
		hasher := fnvNew64a()
		_, _ = hasher.Write([]byte(token))
		h := hasher.Sum64()

		for bit := 0; bit < 64; bit++ {
			if h&(uint64(1)<<bit) != 0 {
				vector[bit]++
			} else {
				vector[bit]--
			}
		}
	}

	var fingerprint uint64
	for bit, weight := range vector {
		if weight > 0 {
			fingerprint |= uint64(1) << bit
		}
	}
	return fingerprint
}

func runeIsSpaceOrPunct(r rune) bool {
	return (r == ' ' || r == '\t' || r == '\n' || r == '\r') || (r == '!' || r == ',' || r == ';' || r == '.')
}

type fnvHash struct {
	state uint64
}

func fnvNew64a() *fnvHash {
	return &fnvHash{state: 14695981039346656037}
}

func (f *fnvHash) Write(data []byte) (int, error) {
	for _, b := range data {
		f.state ^= uint64(b)
		f.state *= 1099511628211
	}
	return len(data), nil
}

func (f *fnvHash) Sum64() uint64 {
	return f.state
}

func BenchmarkSimhashBodyNew(b *testing.B) {
	body := []byte("hello world this is a test with a lot of words to ensure we have a realistic benchmark scenario.")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = simhashBody(body)
	}
}

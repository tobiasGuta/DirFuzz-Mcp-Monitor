package engine

import (
	"hash/fnv"
	"math/bits"
	"strings"
	"unicode"
)

// simhashBody computes a 64-bit SimHash fingerprint for a response body.
func simhashBody(body []byte) uint64 {
	text := string(body)
	tokens := strings.FieldsFunc(text, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsPunct(r)
	})
	if len(tokens) == 0 {
		return 0
	}

	var vector [64]int
	for _, token := range tokens {
		if token == "" {
			continue
		}

		hasher := fnv.New64a()
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

func hammingDistance(a, b uint64) int {
	return bits.OnesCount64(a ^ b)
}

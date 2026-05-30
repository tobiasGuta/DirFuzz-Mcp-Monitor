package engine

import (
	"hash/fnv"
	"math/bits"
	"unicode"
	"unicode/utf8"
)

// simhashBody computes a 64-bit SimHash fingerprint for a response body without allocating.
func simhashBody(body []byte) uint64 {
	if len(body) == 0 {
		return 0
	}

	var vector [64]int
	hasTokens := false

	inToken := false
	tokenStart := 0

	for i := 0; i < len(body); {
		r, size := utf8.DecodeRune(body[i:])
		isBoundary := unicode.IsSpace(r) || unicode.IsPunct(r)

		if isBoundary {
			if inToken {
				token := body[tokenStart:i]
				if len(token) > 0 {
					hashToken(token, &vector)
					hasTokens = true
				}
				inToken = false
			}
		} else {
			if !inToken {
				tokenStart = i
				inToken = true
			}
		}
		i += size
	}

	if inToken {
		token := body[tokenStart:]
		if len(token) > 0 {
			hashToken(token, &vector)
			hasTokens = true
		}
	}

	if !hasTokens {
		return 0
	}

	var fingerprint uint64
	for bit, weight := range vector {
		if weight > 0 {
			fingerprint |= uint64(1) << bit
		}
	}
	return fingerprint
}

func hashToken(token []byte, vector *[64]int) {
	hasher := fnv.New64a()
	_, _ = hasher.Write(token)
	h := hasher.Sum64()

	for bit := 0; bit < 64; bit++ {
		if h&(uint64(1)<<bit) != 0 {
			vector[bit]++
		} else {
			vector[bit]--
		}
	}
}

func hammingDistance(a, b uint64) int {
	return bits.OnesCount64(a ^ b)
}

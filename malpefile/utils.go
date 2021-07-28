package malpefile

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"github.com/gabriel-vasile/mimetype"
	"math"
)

// getMD5 hashes using md5 algorithm.
func getMD5(buf []byte) string {
	h := md5.New()
	h.Write(buf)
	return hex.EncodeToString(h.Sum(nil))
}

// sha256 hashes using md5 algorithm.
func getSHA256(buf []byte) string {
	h := sha256.New()
	h.Write(buf)
	return hex.EncodeToString(h.Sum(nil))
}

func getEntropy(buf []byte) float64 {

	length := float64(len(buf))
	if length == 0.0 {
		return 0.0
	}

	var frequencies [256]uint64
	for _, v := range buf {
		frequencies[v]++
	}

	var entropy float64
	for _, p := range frequencies {
		if p > 0 {
			freq := float64(p) / length
			entropy += freq * math.Log2(freq)
		}
	}

	return -entropy
}

func getType(buf []byte) string {
	mtype := mimetype.Detect(buf)
	return mtype.String()
}

package token

import (
	"crypto/sha256"
	"encoding/hex"
)

func HashToken(token string) (hashedTokenToString string) {
	hashedToken := sha256.Sum256([]byte(token))
	hashedTokenToString = hex.EncodeToString(hashedToken[:])
	return
}

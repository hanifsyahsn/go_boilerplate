package token

import (
	"testing"

	"github.com/hanifsyahsn/go_boilerplate/internal/util"
	"github.com/stretchr/testify/require"
)

func TestHashToken(t *testing.T) {
	token := util.RandomString(6)
	hashedToken := HashToken(token)
	require.NotEmpty(t, hashedToken)
}

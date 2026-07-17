package router_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"neupaneanish.com.np/authentication/internal/config"
	"neupaneanish.com.np/authentication/internal/router"
)

func TestRegister(t *testing.T) {
	t.Parallel()

	_, privateKey, privateKeyErr := ed25519.GenerateKey(nil)
	require.NoError(t, privateKeyErr)
	logger := slog.New(slog.DiscardHandler)

	newJwt, newJwtErr := config.NewJWT(t.Context(), hex.EncodeToString(privateKey.Seed()), "Test", logger)
	require.NoError(t, newJwtErr)
	assert.NotNil(t, newJwt)

	lis, lisErr := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, lisErr)

	serverAdd := lis.Addr().String()
	serverErr := make(chan error, 1)

	port := strings.TrimPrefix(serverAdd, "127.0.0.1:")
	require.NoError(t, lis.Close())

	t.Cleanup(func() {
		select {
		case err := <-serverErr:
			require.NoError(t, err)
		default:
		}
	})

	router.NewRouter(t.Context(), logger, newJwt, port, serverErr)

	const add = `http://%s/%s`

	res, resErr := http.Get(fmt.Sprintf(add, serverAdd, "health"))
	require.NoError(t, resErr)
	defer func() {
		err := res.Body.Close()
		require.NoError(t, err)
	}()
	require.Equal(t, http.StatusOK, res.StatusCode)

	jwksRes, jwksErr := http.Get(fmt.Sprintf(add, serverAdd, ".well-known/jwks.json"))
	require.NoError(t, jwksErr)
	defer func() {
		err := jwksRes.Body.Close()
		require.NoError(t, err)
	}()
	require.Equal(t, http.StatusOK, jwksRes.StatusCode)
}

//go:build integration

package service_test

import (
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"neupaneanish.com.np/authentication/internal/enum"
	rootAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/root/authentication/v1"
)

func TestCounts(t *testing.T) {
	t.Parallel()

	ctx := contextWithValue(t, uuid.New(), enum.UserRoleRoot)

	req := &rootAuthenticationv1.CountsRequest{}

	res, err := rootAuthenticationServiceClient.Counts(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, res)
	assert.GreaterOrEqual(t, res.Users, int64(0))
}

package common

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerificationCodeUsesRedisWhenAvailable(t *testing.T) {
	server := miniredis.RunT(t)
	writer := redis.NewClient(&redis.Options{Addr: server.Addr()})
	reader := redis.NewClient(&redis.Options{Addr: server.Addr()})

	oldRedisEnabled, oldRDB := RedisEnabled, RDB
	RedisEnabled, RDB = true, writer
	t.Cleanup(func() {
		RedisEnabled, RDB = oldRedisEnabled, oldRDB
		require.NoError(t, writer.Close())
		require.NoError(t, reader.Close())
	})

	require.NoError(t, RegisterVerificationCodeWithKey("user@example.com", "123456", EmailVerificationPurpose))

	// A different client represents another application instance sharing Redis.
	RDB = reader
	valid, err := VerifyCodeWithKey("user@example.com", "123456", EmailVerificationPurpose)
	require.NoError(t, err)
	assert.True(t, valid)

	server.FastForward(time.Duration(VerificationValidMinutes) * time.Minute)
	valid, err = VerifyCodeWithKey("user@example.com", "123456", EmailVerificationPurpose)
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestVerificationCodeFallsBackToMemoryWithoutRedis(t *testing.T) {
	oldRedisEnabled, oldRDB := RedisEnabled, RDB
	RedisEnabled, RDB = false, nil
	t.Cleanup(func() {
		RedisEnabled, RDB = oldRedisEnabled, oldRDB
	})

	require.NoError(t, RegisterVerificationCodeWithKey("user@example.com", "123456", EmailVerificationPurpose))

	valid, err := VerifyCodeWithKey("user@example.com", "123456", EmailVerificationPurpose)
	require.NoError(t, err)
	assert.True(t, valid)

	require.NoError(t, DeleteKey("user@example.com", EmailVerificationPurpose))
	valid, err = VerifyCodeWithKey("user@example.com", "123456", EmailVerificationPurpose)
	require.NoError(t, err)
	assert.False(t, valid)
}

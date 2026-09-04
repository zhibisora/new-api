package common

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
)

type verificationValue struct {
	code string
	time time.Time
}

const (
	EmailVerificationPurpose = "v"
	PasswordResetPurpose     = "r"
)

var verificationMutex sync.Mutex
var verificationMap map[string]verificationValue
var verificationMapMaxSize = 10
var VerificationValidMinutes = 10

func verificationRedisKey(key string, purpose string) string {
	digest := sha256.Sum256([]byte(purpose + "\x00" + key))
	return fmt.Sprintf("verification:%x", digest)
}

func useRedisForVerification() bool {
	return RedisEnabled && RDB != nil
}

func GenerateVerificationCode(length int) string {
	code := uuid.New().String()
	code = strings.Replace(code, "-", "", -1)
	if length == 0 {
		return code
	}
	return code[:length]
}

func RegisterVerificationCodeWithKey(key string, code string, purpose string) error {
	if useRedisForVerification() {
		err := RDB.Set(
			context.Background(),
			verificationRedisKey(key, purpose),
			code,
			time.Duration(VerificationValidMinutes)*time.Minute,
		).Err()
		if err != nil {
			return fmt.Errorf("store verification code in Redis: %w", err)
		}
		return nil
	}

	verificationMutex.Lock()
	defer verificationMutex.Unlock()
	verificationMap[purpose+key] = verificationValue{
		code: code,
		time: time.Now(),
	}
	if len(verificationMap) > verificationMapMaxSize {
		removeExpiredPairs()
	}
	return nil
}

func VerifyCodeWithKey(key string, code string, purpose string) (bool, error) {
	if useRedisForVerification() {
		value, err := RDB.Get(context.Background(), verificationRedisKey(key, purpose)).Result()
		if errors.Is(err, redis.Nil) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("load verification code from Redis: %w", err)
		}
		return code == value, nil
	}

	verificationMutex.Lock()
	defer verificationMutex.Unlock()
	value, okay := verificationMap[purpose+key]
	now := time.Now()
	if !okay || int(now.Sub(value.time).Seconds()) >= VerificationValidMinutes*60 {
		return false, nil
	}
	return code == value.code, nil
}

func DeleteKey(key string, purpose string) error {
	if useRedisForVerification() {
		if err := RDB.Del(context.Background(), verificationRedisKey(key, purpose)).Err(); err != nil {
			return fmt.Errorf("delete verification code from Redis: %w", err)
		}
		return nil
	}

	verificationMutex.Lock()
	defer verificationMutex.Unlock()
	delete(verificationMap, purpose+key)
	return nil
}

// no lock inside, so the caller must lock the verificationMap before calling!
func removeExpiredPairs() {
	now := time.Now()
	for key := range verificationMap {
		if int(now.Sub(verificationMap[key].time).Seconds()) >= VerificationValidMinutes*60 {
			delete(verificationMap, key)
		}
	}
}

func init() {
	verificationMutex.Lock()
	defer verificationMutex.Unlock()
	verificationMap = make(map[string]verificationValue)
}

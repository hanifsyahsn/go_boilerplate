package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type Client interface {
	Get(key string) (string, error)
	Set(key string, value interface{}, ttl time.Duration) error
	Del(key string) error
	Close() error
}

type Redis struct {
	Rdb *redis.Client
}

func NewRedisClient(redis *redis.Client) *Redis {
	return &Redis{
		Rdb: redis,
	}
}

func (r *Redis) Get(key string) (string, error) {
	return r.Rdb.Get(context.Background(), key).Result()
}

func (r *Redis) Set(key string, value interface{}, ttl time.Duration) error {
	return r.Rdb.Set(context.Background(), key, value, ttl).Err()
}

func (r *Redis) Del(key string) error {
	return r.Rdb.Del(context.Background(), key).Err()
}

func (r *Redis) Close() error {
	return r.Rdb.Close()
}

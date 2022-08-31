package cache

import (
	"github.com/go-redis/redis"
)

type RedisCache struct {
	Host string
	DB   int
}

func (cache *RedisCache) getClient() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     cache.Host,
		Password: "",
		DB:       cache.DB,
	})
}

package redis

import (
	"context"
	goRedis "github.com/redis/go-redis/v9"
	"time"
)

func SetToRedis(redCli *goRedis.Client, ctx context.Context, key, value string, ttls int) error {

	if err := redCli.Set(ctx, key, value, time.Duration(ttls)*time.Second).Err(); err != nil {
		return err
	}

	return nil

}

func GetFromRedis(redCli *goRedis.Client, ctx context.Context, key string) (string, error) {

	result, err := redCli.Get(ctx, key).Result()

	if err != nil {
		return "", err
	}

	return result, nil

}

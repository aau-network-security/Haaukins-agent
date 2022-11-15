package state

import (
	env "github.com/aau-network-security/haaukins-agent/internal/environment"
	"github.com/go-redis/redis"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog/log"
)

func (cache *RedisCache) getClient() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     cache.Host,
		Password: "",
		DB:       cache.DB,
	})
}

func (cache *RedisCache) SaveState(envPool *env.EnvPool) error {
	client := cache.getClient()
	state := State{
		Environments: make(map[string]Environment),
	}
	for k, env := range envPool.Envs {
		envState := makeEnvState(env)
		state.Environments[k] = envState
	}

	jsonState, err := json.Marshal(state)
	if err != nil {
		log.Error().Err(err).Msg("error marshalling state")
		return err
	}

	client.Set("state", string(jsonState), 0)

	return nil
}

func (cache *RedisCache) ResumeState() (*State, error) {

	return nil, nil
}

// TODO: Make functions to assemble the state based on the environmentPool
func makeEnvState(env *env.Environment) Environment {

	return Environment{}
}

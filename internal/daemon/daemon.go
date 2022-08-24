package daemon

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"time"

	"google.golang.org/grpc"

	pb "github.com/aau-network-security/haaukins-agent/internal/proto"
	"github.com/aau-network-security/haaukins-agent/internal/virtual/docker"
	"github.com/aau-network-security/haaukins/virtual"
	"github.com/go-redis/redis"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Host          string `yaml:"host"`
	Port          uint   `yaml:"port"`
	AuthKey       string `yaml:"auth-key"`
	SignKey       string `yaml:"sign-key"`
	RedisDataPath string `yaml:"redis-data-path"`
}

type Daemon struct {
	cache *redis.Client
	auth  Authenticator
	pb.UnimplementedAgentServer
}

const DEFAULT_SIGN = "dev-sign-key"
const DEFAULT_AUTH = "dev-auth-key"

func NewConfigFromFile(path string) (*Config, error) {
	f, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var c Config
	err = yaml.Unmarshal(f, &c)
	if err != nil {
		return nil, err
	}

	if c.Host == "" {
		log.Debug().Msg("host not provided in the configuration file")
		c.Host = "localhost"
	}

	if c.Port == 0 {
		log.Debug().Msg("port not provided in the configuration file")
		c.Port = 50095
	}

	if c.SignKey == "" {
		log.Debug().Msg("signinKey not provided in the configuration file")
		c.SignKey = DEFAULT_SIGN
	}

	if c.AuthKey == "" {
		log.Debug().Msg("authKey not provided in the configuration file")
		c.AuthKey = DEFAULT_AUTH
	}

	if c.RedisDataPath == "" {
		log.Debug().Msg("redisDataPath not provided in the configuration file")
		pwd, err := os.Getwd()
		if err != nil {
			log.Fatal().Err(err).Msg("failed to get current working directory for redis")
		}
		c.RedisDataPath = pwd + "/data"
	}
	return &c, nil
}

func New(conf *Config) (*Daemon, error) {
	ctx := context.Background()
	// Setting up the redis container
	if _, err := os.Stat(conf.RedisDataPath); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(conf.RedisDataPath, os.ModePerm)
		if err != nil {
			log.Error().Err(err).Msg("Error creating dir")
		}
	}

	container, err := docker.GetRedisContainer(conf.RedisDataPath)
	if err != nil {
		log.Error().Err(err).Msg("error getting container state")
		return nil, err
	}

	if container != nil {
		log.Debug().Msg("Found already existing redis container")
		log.Debug().Msgf("Container info: %v", container.Info())
		if container.Info().State == virtual.Stopped || container.Info().State == virtual.Suspended {
			log.Debug().Msg("Container not running, restarting the container...")
			if err := container.Start(ctx); err != nil {
				log.Fatal().Err(err).Msg("Failed to start existing redis container")
			}
			// Waiting for container to start
			time.Sleep(5)
		} else {
			log.Debug().Msg("Container already running, continueing...")
		}
	} else {
		log.Info().Msg("No redis container detected, creating a new one")
		container = docker.NewContainer(docker.ContainerConfig{
			Image:     "redis:7.0.4",
			Name:      "redis_cache",
			UseBridge: true,
			Mounts: []string{
				conf.RedisDataPath + ":/data",
			},
			PortBindings: map[string]string{
				"6379": "127.0.0.1:6379",
			},
		})
		if err := container.Run(ctx); err != nil {
			log.Fatal().Err(err).Msg("Error running new redis container")
		}
		// Waiting for container to start
		time.Sleep(5)
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr:     "127.0.0.1:6379",
		Password: "",
		DB:       0,
	})

	_, err = redisClient.Ping().Result()
	if err != nil {
		log.Fatal().Err(err).Msg("error connecting to redis cache")
	}

	//log.Debug().Int("State", int(redisContainer.Info().State))
	d := &Daemon{
		cache: redisClient,
		auth:  NewAuthenticator(conf.SignKey, conf.AuthKey),
	}
	return d, nil
}

func (d *Daemon) NewGRPCServer(opts ...grpc.ServerOption) *grpc.Server {

	streamInterceptor := func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := d.auth.AuthenticateContext(stream.Context()); err != nil {
			return err
		}
		return handler(srv, stream)
	}

	unaryInterceptor := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if err := d.auth.AuthenticateContext(ctx); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}

	opts = append([]grpc.ServerOption{
		grpc.StreamInterceptor(streamInterceptor),
		grpc.UnaryInterceptor(unaryInterceptor),
	}, opts...)
	return grpc.NewServer(opts...)
}

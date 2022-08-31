package agent

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"

	"github.com/aau-network-security/haaukins-agent/internal/cache"
	pb "github.com/aau-network-security/haaukins-agent/internal/proto"
	"github.com/aau-network-security/haaukins-agent/internal/virtual/docker"
	eproto "github.com/aau-network-security/haaukins-exercises/proto"
	"github.com/aau-network-security/haaukins/virtual"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

type Agent struct {
	redis cache.RedisCache
	State *State
	auth  Authenticator
	pb.UnimplementedAgentServer
}

type State struct {
	m         sync.RWMutex
	Eventpool *eventPool `json:"eventpool,omitempty"`
	exClient  eproto.ExerciseStoreClient
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

	pwd, err := os.Getwd()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to get current working directory for redis")
	}
	if c.RedisDataPath == "" {
		log.Debug().Msg("redisDataPath not provided in the configuration file")
		c.RedisDataPath = filepath.Join(pwd, "data")
	}

	if c.FileTransferRoot == "" {
		log.Debug().Msg("filetransfer root not provided in the configuration file")
		c.RedisDataPath = filepath.Join(pwd, "filetransfer")
	}

	if c.OvaDir == "" {
		log.Debug().Msg("ova dir not provided in the configuration file")
		c.RedisDataPath = filepath.Join(pwd, "vms")
	}

	for _, repo := range c.DockerRepositories {
		docker.Registries[repo.ServerAddress] = repo
	}

	return &c, nil
}

func New(conf *Config) (*Agent, error) {
	ctx := context.Background()
	// Setting up the redis container
	if _, err := os.Stat(conf.RedisDataPath); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(conf.RedisDataPath, os.ModePerm)
		if err != nil {
			log.Error().Err(err).Msg("Error creating dir")
		}
	}

	// Check if redis is running
	container, err := docker.GetRedisContainer(conf.RedisDataPath)
	if err != nil {
		log.Error().Err(err).Msg("error getting container state")
		return nil, err
	}

	// Container exists checking the state to start the container if it has been stopped
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
		// Didn't detect the redis container, starting a new one...
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

	//log.Debug().Int("State", int(redisContainer.Info().State))
	d := &Agent{
		redis: cache.RedisCache{
			Host: "127.0.0.1:6379",
			DB:   0,
		},
		auth: NewAuthenticator(conf.SignKey, conf.AuthKey),
	}
	return d, nil
}

func (d *Agent) NewGRPCServer(opts ...grpc.ServerOption) *grpc.Server {

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

package agent

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/aau-network-security/haaukins-agent/internal/state"
	"google.golang.org/grpc"

	env "github.com/aau-network-security/haaukins-agent/internal/environment"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
	"github.com/aau-network-security/haaukins-agent/internal/worker"
	pb "github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

var configPath string

type Agent struct {
	config *Config
	State  *state.State
	auth   Authenticator
	vlib   *virtual.VboxLibrary
	pb.UnimplementedAgentServer
	workerPool worker.WorkerPool
	newLabs    chan pb.Lab
	EnvPool    *env.EnvPool `json:"envpool,omitempty"`
}

const DEFAULT_SIGN = "dev-sign-key"
const DEFAULT_AUTH = "dev-auth-key"

// TODO check vpn service conf
func NewConfigFromFile(path string) (*Config, error) {
	configPath = path
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

	if c.GrpcPort == 0 {
		log.Debug().Int("port", 50095).Msg("port not provided in the configuration file using default")
		c.GrpcPort = 50095
	}

	if c.SignKey == "" {
		log.Debug().Msg("signinKey not provided in the configuration file")
		c.SignKey = DEFAULT_SIGN
	}

	if c.AuthKey == "" {
		log.Debug().Msg("authKey not provided in the configuration file")
		c.AuthKey = DEFAULT_AUTH
	}

	if c.MaxWorkers == 0 {
		c.MaxWorkers = 5
	}

	// In case paths has not been set, use working directory
	pwd, err := os.Getwd()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to get current working directory")
	}
	if c.StatePath == "" {
		log.Fatal().Msg("statepath not provided in the configuration file\n Please provide a path for the state file to be saved")
	}

	if c.FileTransferRoot == "" {
		log.Debug().Msg("filetransfer root not provided in the configuration file")
		c.FileTransferRoot = filepath.Join(pwd, "filetransfer")
	}

	if c.OvaDir == "" {
		log.Debug().Msg("ova dir not provided in the configuration file")
		c.OvaDir = filepath.Join(pwd, "vms")
	}

	for _, repo := range c.DockerRepositories {
		virtual.Registries[repo.ServerAddress] = repo
	}

	return &c, nil
}

func New(conf *Config) (*Agent, error) {
	// Creating filetransfer root if not exists
	err := virtual.CreateFileTransferRoot(conf.FileTransferRoot)
	if err != nil {
		log.Fatal().Msgf("Error while creating file transfer root: %s", err)
	}

	// Setting up the state path
	if _, err := os.Stat(conf.StatePath); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(conf.StatePath, os.ModePerm)
		if err != nil {
			log.Error().Err(err).Msg("Error creating dir")
		}
	}

	// Creating and starting a workerPool for lab creation
	// This is to ensure that resources are not spent without having them
	// Workeramount can be configured from the config
	workerPool := worker.NewWorkerPool(conf.MaxWorkers)
	workerPool.Run()

	vlib := virtual.NewLibrary(conf.OvaDir)

	envPool, err := state.ResumeState(vlib, workerPool, conf.StatePath)
	if err != nil {
		log.Error().Err(err).Msg("error resuming state")
		envPool = &env.EnvPool{
			M:            &sync.RWMutex{},
			Envs:         make(map[string]*env.Environment),
			StartingEnvs: make(map[string]bool),
			ClosingEnvs:  make(map[string]bool),
		}
	}
	if envPool == nil {
		envPool = &env.EnvPool{
			M:            &sync.RWMutex{},
			Envs:         make(map[string]*env.Environment),
			StartingEnvs: make(map[string]bool),
			ClosingEnvs:  make(map[string]bool),
		}
	}
	// Creating agent struct
	a := &Agent{
		config:     conf,
		workerPool: workerPool,
		vlib:       vlib,
		auth:       NewAuthenticator(conf.SignKey, conf.AuthKey),
		newLabs:    make(chan pb.Lab, 1000),
		EnvPool:    envPool,
		State:      &state.State{},
	}
	return a, nil
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

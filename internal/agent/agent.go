package agent

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/aau-network-security/haaukins-agent/internal/state"
	"google.golang.org/grpc"

	env "github.com/aau-network-security/haaukins-agent/internal/environment"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
	"github.com/aau-network-security/haaukins-agent/internal/worker"
	"github.com/aau-network-security/haaukins-agent/pkg/proto"
	pb "github.com/aau-network-security/haaukins-agent/pkg/proto"
	eproto "github.com/aau-network-security/haaukins-exercises/proto"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

var configPath string

type Agent struct {
	initialized bool
	config      *Config
	State       *state.State
	auth        Authenticator
	vlib        *virtual.VboxLibrary
	pb.UnimplementedAgentServer
	workerPool worker.WorkerPool
	newLabs    chan pb.Lab
	ExClient   eproto.ExerciseStoreClient
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
		log.Debug().Msg("port not provided in the configuration file")
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

	var initialized = true
	var exClient eproto.ExerciseStoreClient
	// Check if exercise service has been configured by daemon
	if conf.ExerciseService.Grpc == "" {
		log.Debug().Msg("exercise service not yet configured, waiting for daemon to initiliaze...")
		initialized = false
		exClient = nil
	} else {
		exClient, err = NewExerciseClientConn(conf.ExerciseService)
		if err != nil {
			return nil, fmt.Errorf("error connecting to exercise service: %s", err)
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
			M:    &sync.RWMutex{},
			Envs: make(map[string]*env.Environment),
		}
	}
	if envPool == nil {
		envPool = &env.EnvPool{
			M:    &sync.RWMutex{},
			Envs: make(map[string]*env.Environment),
		}
	}
	// Creating agent struct
	a := &Agent{
		initialized: initialized,
		config:      conf,
		workerPool:  workerPool,
		vlib:        vlib,
		auth:        NewAuthenticator(conf.SignKey, conf.AuthKey),
		newLabs:     make(chan pb.Lab, 100),
		ExClient:    exClient,
		EnvPool:     envPool,
		State:       &state.State{},
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

// Connect to exdb based on what creds sent by daemon, and write to config
func (a *Agent) Init(ctx context.Context, req *proto.InitRequest) (*proto.StatusResponse, error) {
	// Creating service config based on request from daemon
	var exConf = ServiceConfig{
		Grpc:       req.Url,
		AuthKey:    req.AuthKey,
		SignKey:    req.SignKey,
		TLSEnabled: req.TlsEnabled,
	}
	// Creating new exercise service connection from config
	log.Debug().Msgf("request: %v", req)
	exClient, err := NewExerciseClientConn(exConf)
	if err != nil {
		log.Error().Err(err).Msg("error connecting to exercise service")
		return nil, fmt.Errorf("error connecting to exercise service: %s", err)
	}

	// Saving the config in the agent config
	a.config.ExerciseService = exConf

	// Updating the config
	data, err := yaml.Marshal(a.config)
	if err != nil {
		log.Error().Err(err).Msg("error marshalling yaml")
		return nil, fmt.Errorf("error marshalling yaml: %s", err)
	}

	// Truncates existing file to overwrite with new data
	f, err := os.Create(configPath)
	if err != nil {
		log.Error().Err(err).Msg("error creating or truncating config file")
		return nil, fmt.Errorf("error creating or truncating config file: %s", err)
	}

	if err := f.Chmod(0600); err != nil {
		log.Error().Err(err).Msg("error changing file perms")
		return nil, fmt.Errorf("error changing file perms: %s", err)
	}

	if _, err := f.Write(data); err != nil {
		log.Error().Err(err).Msg("error writing config to file")
		return nil, fmt.Errorf("error writing config to file: %s", err)
	}
	a.initialized = true
	a.ExClient = exClient
	return &proto.StatusResponse{Message: "OK"}, nil
}

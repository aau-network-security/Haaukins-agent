package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aau-network-security/haaukins-agent/internal/environment"
	env "github.com/aau-network-security/haaukins-agent/internal/environment"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/exercise"
	wg "github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/vpn"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual/vbox"
	"github.com/aau-network-security/haaukins-agent/pkg/proto"
	eproto "github.com/aau-network-security/haaukins-exercises/proto"
	"github.com/rs/zerolog/log"
)

var (
	vpnIPPool = newIPPoolFromHost()
)

/* Creates a new lab environment for a new event.
Labs can afterwards be added using the CreateLabsForEnv call */
// TODO Check if environment exists, figure out what the logic should be.
func (a *Agent) CreateEnvironment(ctx context.Context, req *proto.CreatEnvRequest) (*proto.StatusResponse, error) {
	// Env for event already exists, Do not start a new guac container
	if !a.initialized {
		return nil, errors.New("agent not yet initialized")
	}
	log.Debug().Msgf("got createEnv request: %v", req)

	// Create a new environment for event if it does not exists
	// Setting up the env config
	var envConf env.EnvConfig
	envConf.Tag = req.EventTag
	envConf.Type = lab.LabType(req.EnvType)
	envConf.WorkerPool = a.workerPool
	log.Debug().Str("envtype", envConf.Type.String()).Msg("making environment with type")
	// Get exercise info from exercise db

	exerDbConfs, err := a.State.ExClient.GetExerciseByTags(ctx, &eproto.GetExerciseByTagsRequest{Tag: req.Exercises})
	if err != nil {
		return nil, fmt.Errorf("error getting exercises: %s", err)
	}
	// Unpack into exercise slice
	var exerConfs []exercise.ExerciseConfig
	for _, e := range exerDbConfs.Exercises {
		ex, err := protobufToJson(e)
		if err != nil {
			return nil, err
		}
		estruct := exercise.ExerciseConfig{}
		json.Unmarshal([]byte(ex), &estruct)
		exerConfs = append(exerConfs, estruct)
	}
	envConf.LabConf.ExerciseConfs = exerConfs

	// Insert frontends for environment into environment config
	var frontends = []vbox.InstanceConfig{}
	for _, f := range req.Vms {
		frontend := vbox.InstanceConfig{
			Image:    f.Image,
			MemoryMB: uint(f.MemoryMB),
			CPU:      f.Cpu,
		}
		frontends = append(frontends, frontend)
	}
	envConf.LabConf.Frontends = append(envConf.LabConf.Frontends, frontends...)

	// Set the vlib
	envConf.LabConf.Vlib = a.vlib

	// Get VPN address for environment if participant want to switch from browser to VPN
	vpnIP, err := getVPNIP()
	if err != nil {
		log.Error().Err(err).Msg("error getting vpn ip address")
		return nil, err
	}
	vpnAddress := fmt.Sprintf("%s.240.1/22", vpnIP)
	envConf.VPNAddress = vpnAddress
	envConf.VpnConfig = wg.WireGuardConfig{
		Endpoint: a.config.VPNService.Endpoint,
		Port:     a.config.VPNService.Port,
		AuthKey:  a.config.VPNService.AuthKey,
		SignKey:  a.config.VPNService.SignKey,
		Enabled:  a.config.VPNService.TLSEnabled,
		Dir:      a.config.VPNService.WgConfDir,
	}

	// Create environment
	env, err := envConf.NewEnv(ctx, a.newLabs, req.InitialLabs)
	if err != nil {
		log.Error().Err(err).Msg("error creating environment")
		return &proto.StatusResponse{Message: "Error creating environment"}, err
	}
	// TODO Still need to figure out how to keep the state of the agent

	// Start the environment
	go env.Start(context.TODO())

	// TODO add env to envpool, make function?
	a.State.EnvPool.AddEnv(&env)

	return &proto.StatusResponse{Message: "recieved createLabs request... starting labs"}, nil
}

// Closes environment and attached containers/vms, and removes the environment from the event pool
func (a *Agent) CloseEnvironment(ctx context.Context, req *proto.CloseEnvRequest) (*proto.StatusResponse, error) {
	env, err := a.State.EnvPool.GetEnv(req.EventTag)
	if err != nil {
		log.Error().Str("envTag", req.EventTag).Msg("error finding finding environment with tag")
		return nil, fmt.Errorf("error finding environment with tag: %s", req.EventTag)
	}

	env.EnvConfig.Status = environment.StatusClosing

	envConf := env.EnvConfig

	vpnIP := strings.ReplaceAll(envConf.VPNAddress, ".240.1/22", "")
	vpnIPPool.ReleaseIP(vpnIP)

	if err := vbox.RemoveEventFolder(string(envConf.Tag)); err != nil {
		//do nothing
	}

	if err := env.Close(); err != nil {
		log.Error().Err(err).Msg("error closing environment")
		return nil, fmt.Errorf("error closing environment %v", err)
	}

	env.EnvConfig.Status = environment.StatusClosed

	a.State.EnvPool.RemoveEnv(envConf.Tag)

	return &proto.StatusResponse{Message: "OK"}, nil
}

// Adds exercises to a beginner environment
// It appends the new exercise configs to the existing lab config within the environment.
// This is used for future labs that may start up.
// Then it adds the exercises to the existing running labs under this environment.
func (a *Agent) AddExercisesToEnv(ctx context.Context, req *proto.AddExercisesRequest) (*proto.StatusResponse, error) {
	env, ok := a.State.EnvPool.Envs[req.EnvTag]
	if !ok {
		log.Error().Str("envTag", req.EnvTag).Msg("error finding finding environment with tag")
		return nil, fmt.Errorf("error finding environment with tag: %s", req.EnvTag)
	}

	if env.EnvConfig.Type == lab.TypeAdvanced {
		return nil, errors.New("you cannot add exercises to advanced typed environments... use AddExercisesToLab as users manage their own exercises")
	}

	env.M.Lock()
	defer env.M.Unlock()

	exerDbConfs, err := a.State.ExClient.GetExerciseByTags(ctx, &eproto.GetExerciseByTagsRequest{Tag: req.Exercises})
	if err != nil {
		return nil, fmt.Errorf("error getting exercises: %s", err)
	}
	// Unpack into exercise slice
	var exerConfs []exercise.ExerciseConfig
	for _, e := range exerDbConfs.Exercises {
		ex, err := protobufToJson(e)
		if err != nil {
			return nil, err
		}
		estruct := exercise.ExerciseConfig{}
		json.Unmarshal([]byte(ex), &estruct)
		exerConfs = append(exerConfs, estruct)
	}
	env.EnvConfig.LabConf.ExerciseConfs = append(env.EnvConfig.LabConf.ExerciseConfs, exerConfs...)

	var wg sync.WaitGroup
	ctx = context.Background()
	for k := range env.Labs {
		wg.Add(1)
		l := env.Labs[k]
		a.workerPool.AddTask(func() {
			log.Debug().Str("labTag", l.Tag).Msg("adding exercises for lab")
			if err := l.AddAndStartExercises(ctx, exerConfs...); err != nil {
				log.Error().Str("labTag", l.Tag).Err(err).Msg("error adding and starting exercises for lab")
			}
			wg.Done()
		})
	}
	wg.Wait()

	return &proto.StatusResponse{Message: "OK"}, nil
}

func getVPNIP() (string, error) {
	// Get VPN IP address from ip pool
	ip, err := vpnIPPool.Get()
	if err != nil {
		return "", err
	}
	return ip, nil
}

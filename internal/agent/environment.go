package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	env "github.com/aau-network-security/haaukins-agent/internal/environment"
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
	envConf.WorkerPool = a.workerPool

	// Get exercise info from exercise db
	var exerConfs []exercise.ExerciseConfig
	exerDbConfs, err := a.State.ExClient.GetExerciseByTags(ctx, &eproto.GetExerciseByTagsRequest{Tag: req.Exercises})
	if err != nil {
		return nil, errors.New(fmt.Sprintf("error getting exercises: %s", err))
	}
	//log.Debug().Msgf("challenges: %v", exerDbConfs)
	// Unpack into exercise slice
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
	env, err := envConf.NewEnv(ctx, a.newLabs, req.LabAmount)
	if err != nil {
		log.Error().Err(err).Msg("error creating environment")
		return &proto.StatusResponse{Message: "Error creating environment"}, err
	}
	// TODO Still need to figure out how to keep the state of the agent

	// Start the environment
	go env.Start(context.TODO())

	// TODO add env to envpool
	a.State.EnvPool.Em.Lock()
	a.State.EnvPool.Envs[env.EnvConfig.Tag] = env
	a.State.EnvPool.Em.Unlock()

	a.State.EnvPool.Em.RLock()
	for k, _ := range a.State.EnvPool.Envs {
		log.Debug().Str("key", k).Msg("envs in env pool")
	}
	a.State.EnvPool.Em.RUnlock()
	return &proto.StatusResponse{Message: "recieved createLabs request... starting labs"}, nil
}

func getVPNIP() (string, error) {
	// Get VPN IP address from ip pool
	ip, err := vpnIPPool.Get()
	if err != nil {
		return "", err
	}
	return ip, nil
}

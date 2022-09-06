package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	env "github.com/aau-network-security/haaukins-agent/internal/environment"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
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
func (a *Agent) CreateEnvironment(ctx context.Context, req *proto.CreatEnvRequest) (*proto.StatusResponse, error) {
	// Env for event already exists, Do not start a new guac container
	if !a.initialized {
		return nil, errors.New("agent not yet initialized")
	}

	// Create a new environment for event if it does not exists
	// Setting up the env config
	var envConf env.EnvConfig
	envConf.Tag = req.EventTag

	// Get exercise info from exercise db
	var exers []lab.Exercise
	exer, err := a.State.ExClient.GetExerciseByTags(ctx, &eproto.GetExerciseByTagsRequest{Tag: req.Exercises})
	if err != nil {
		return nil, errors.New(fmt.Sprintf("error getting exercises: %s", err))
	}
	log.Debug().Msgf("challenges: %v", exer)
	// Unpack into exercise slice
	for _, e := range exer.Exercises {
		exercise, err := protobufToJson(e)
		if err != nil {
			return nil, err
		}
		estruct := lab.Exercise{}
		json.Unmarshal([]byte(exercise), &estruct)
		exers = append(exers, estruct)
	}
	envConf.Exercises = exers

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
	envConf.Frontends = append(envConf.Frontends, frontends...)

	// Set the vlib
	envConf.Vlib = a.vlib

	// Get VPN address for environment if participant want to switch from browser to VPN
	VPNAddress, err := getVPNIP()
	if err != nil {
		log.Error().Err(err).Msg("error getting vpn ip address")
		return nil, err
	}
	envConf.VPNAddress = VPNAddress

	// Create environment

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

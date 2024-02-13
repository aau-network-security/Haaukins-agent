package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/aau-network-security/haaukins-agent/internal/environment"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/exercise"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
	"github.com/aau-network-security/haaukins-agent/internal/state"
	"github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/rs/zerolog/log"
)

func (a *Agent) CreateLabForEnv(ctx context.Context, req *proto.CreateLabRequest) (*proto.StatusResponse, error) {
	env, err := a.EnvPool.GetEnv(req.EventTag)
	if err != nil {
		return nil, errors.New("environment for event does not exist")
	}

	if env.EnvConfig.Type == lab.TypeBeginner && req.IsVPN {
		return nil, errors.New("cannot create vpn lab for beginner environment")
	}

	ec := env.EnvConfig

	m := &sync.RWMutex{}
	ec.WorkerPool.AddTask(func() {
		ctx := context.Background()
		log.Debug().Uint8("envStatus", uint8(ec.Status)).Msg("environment status when starting worker")
		// Make sure that environment is still running before creating lab
		if ec.Status == environment.StatusClosing || ec.Status == environment.StatusClosed {
			log.Info().Msg("environment closed before newlab task was taken from queue, canceling...")
			return
		}

		// Creating containers etc.
		l, err := ec.LabConf.NewLab(ctx, req.IsVPN, ec.Type, ec.Tag)
		if err != nil {
			log.Error().Err(err).Str("eventTag", env.EnvConfig.Tag).Msg("error creating new lab")
			return
		}
		// Starting the created containers and frontends
		if err := l.Start(ctx); err != nil {
			log.Error().Err(err).Str("eventTag", env.EnvConfig.Tag).Msg("error starting new lab")
			return
		}

		if !l.IsVPN {
			if err := env.CreateGuacConn(l); err != nil {
				log.Error().Err(err).Str("labTag", l.Tag).Msg("error creating guac connection for lab")
			}
		} else {
			env.M.Lock()

			labSubnet := fmt.Sprintf("%s/24", l.DhcpServer.Subnet)

			vpnConfig := lab.VpnConfig{
				Host:            a.config.Host,
				VpnAddress:      env.EnvConfig.VPNAddress,
				VPNEndpointPort: env.EnvConfig.VPNEndpointPort,
				IpAddresses:     env.IpAddrs,
				LabSubnet:       labSubnet,
				TeamSize:        env.EnvConfig.TeamSize,
			}

			labConfigsFiles, vpnIPs, _ := l.CreateVPNConfigs(env.Wg, req.EventTag, vpnConfig)

			env.IpT.CreateRejectRule(labSubnet)
			env.IpT.CreateStateRule(labSubnet)
			env.IpT.CreateAcceptRule(labSubnet, strings.Join(vpnIPs, ","))
			env.IpRules[l.Tag] = environment.IpRules{
				Labsubnet: labSubnet,
				VpnIps:    strings.Join(vpnIPs, ","),
			}
			l.VpnConfs = labConfigsFiles
			env.M.Unlock()
		}

		log.Debug().Uint8("envStatus", uint8(ec.Status)).Msg("environment status when ending worker")
		if ec.Status == environment.StatusClosing || ec.Status == environment.StatusClosed {
			log.Info().Msg("environment closed while newlab task was running from queue, closing lab...")
			if err := l.Close(); err != nil {
				log.Error().Err(err).Msg("error closing lab")
				return
			}
			return
		}

		// Sending lab info to daemon
		newLab := proto.Lab{
			Tag:       l.Tag,
			EventTag:  ec.Tag,
			Exercises: l.GetExercisesInfo(),
			IsVPN:     req.IsVPN,
			GuacCreds: &proto.GuacCreds{
				Username: l.GuacUsername,
				Password: l.GuacPassword,
			},
			VpnConfs: l.VpnConfs,
		}

		//a.newLabs = append(a.newLabs, newLab)
		a.newLabs <- newLab
		m.Lock()
		env.Labs[l.Tag] = &l
		m.Unlock()
		// Should not be removed as it runs inside a worker
		if err := state.SaveState(a.EnvPool, a.config.StatePath); err != nil {
			log.Error().Err(err).Msg("error saving state")
		}
		// If lab was created while running CloseEnvironment, close the lab
	})
	return &proto.StatusResponse{Message: "OK"}, nil
}

func (a *Agent) GetLab(ctx context.Context, req *proto.GetLabRequest) (*proto.GetLabResponse, error) {
	l, err := a.EnvPool.GetLabByTag(req.LabTag)
	if err != nil {
		log.Error().Str("labTag", req.LabTag).Err(err).Msg("error getting lab by tag")
		return nil, err
	}
	eventTag := strings.Split(l.Tag, "-")[0]

	labToReturn := &proto.Lab{
		Tag:       l.Tag,
		EventTag:  eventTag,
		Exercises: l.GetExercisesInfo(),
		IsVPN:     l.IsVPN,
		GuacCreds: &proto.GuacCreds{
			Username: l.GuacUsername,
			Password: l.GuacPassword,
		},
		VpnConfs: l.VpnConfs,
	}
	return &proto.GetLabResponse{Lab: labToReturn}, nil
}

func (a *Agent) CreateVpnConfForLab(ctx context.Context, req *proto.CreateVpnConfRequest) (*proto.CreateVpnConfResponse, error) {
	l, err := a.EnvPool.GetLabByTag(req.LabTag)
	if err != nil {
		log.Error().Str("labTag", req.LabTag).Err(err).Msg("error getting lab by tag")
		return nil, err
	}

	if !l.IsVPN {
		return nil, errors.New("cannot create vpn connection for lab that is not a VPN lab")
	}

	envTag := strings.Split(l.Tag, "-")[0]

	env, err := a.EnvPool.GetEnv(envTag)
	if err != nil {
		log.Error().Str("envTag", envTag).Msg("error finding finding environment with tag")
		return nil, fmt.Errorf("error finding environment with tag: %s", envTag)
	}
	env.M.Lock()
	defer func() {
		env.M.Unlock()
		if err := state.SaveState(a.EnvPool, a.config.StatePath); err != nil {
			log.Error().Err(err).Msg("error saving state")
		}
	}()

	if _, ok := env.IpRules[l.Tag]; ok {
		return nil, errors.New("VPN configs already generated for this lab")
	}

	labSubnet := fmt.Sprintf("%s/24", l.DhcpServer.Subnet)

	vpnConfig := lab.VpnConfig{
		Host:            a.config.Host,
		VpnAddress:      env.EnvConfig.VPNAddress,
		VPNEndpointPort: env.EnvConfig.VPNEndpointPort,
		IpAddresses:     env.IpAddrs,
		LabSubnet:       labSubnet,
		TeamSize:        env.EnvConfig.TeamSize,
	}

	labConfigsFiles, vpnIPs, err := l.CreateVPNConfigs(env.Wg, envTag, vpnConfig)

	env.IpT.CreateRejectRule(labSubnet)
	env.IpT.CreateStateRule(labSubnet)
	env.IpT.CreateAcceptRule(labSubnet, strings.Join(vpnIPs, ","))
	env.IpRules[l.Tag] = environment.IpRules{
		Labsubnet: labSubnet,
		VpnIps:    strings.Join(vpnIPs, ","),
	}

	return &proto.CreateVpnConfResponse{Configs: labConfigsFiles}, nil
}

func (a *Agent) GetHostsInLab(ctx context.Context, req *proto.GetHostsRequest) (*proto.GetHostsResponse, error) {
	l, err := a.EnvPool.GetLabByTag(req.LabTag)
	if err != nil {
		log.Error().Str("labTag", req.LabTag).Err(err).Msg("error getting lab by tag")
		return nil, err
	}

	hosts := lab.GetDNSRecords(l.DnsRecords)

	return &proto.GetHostsResponse{Hosts: hosts}, nil
}

// Reset lab resets DHCP, DNS, exercises and frontends in lab
func (a *Agent) ResetLab(ctx context.Context, req *proto.ResetLabRequest) (*proto.StatusResponse, error) {
	l, err := a.EnvPool.GetLabByTag(req.LabTag)
	if err != nil {
		log.Error().Str("labTag", req.LabTag).Err(err).Msg("error getting lab by tag")
		return nil, err
	}

	l.M.Lock()
	defer func() {
		l.M.Unlock()
		if err := state.SaveState(a.EnvPool, a.config.StatePath); err != nil {
			log.Error().Err(err).Msg("error saving state")
		}
	}()
	// Reset the DHCP
	if err := l.RefreshDHCP(ctx); err != nil {
		log.Error().Err(err).Str("labTag", req.LabTag).Msg("error resetting DHCP")
		return nil, err
	}

	// Reset the DNS
	if err := l.RefreshDNS(ctx); err != nil {
		log.Error().Err(err).Str("labTag", req.LabTag).Msg("error resetting DNS")
		return nil, err
	}

	// Reset all existing exercises
	for _, exercise := range l.Exercises {
		if err := exercise.Reset(ctx); err != nil {
			log.Error().Err(err).Str("exerciseTag", exercise.Tag).Msg("error resetting exercise")
			return nil, err
		}
	}

	// Stop then start all frontends
	for _, conf := range l.Frontends {
		switch conf.Vm.Info().State {
		case virtual.Running:
			if err := conf.Vm.Stop(); err != nil {
				return nil, err
			}
			if err := conf.Vm.Start(ctx); err != nil {
				return nil, err
			}
		case virtual.Stopped:
			if err := conf.Vm.Start(ctx); err != nil {
				return nil, err
			}
		case virtual.Suspended:
			if err := conf.Vm.Start(ctx); err != nil {
				return nil, err
			}
			if err := conf.Vm.Stop(); err != nil {
				return nil, err
			}
			if err := conf.Vm.Start(ctx); err != nil {
				return nil, err
			}
		case virtual.Error:
			if err := conf.Vm.Create(ctx); err != nil {
				return nil, err
			}
			if err := conf.Vm.Start(ctx); err != nil {
				return nil, err
			}
		}
	}
	
	return &proto.StatusResponse{Message: "OK"}, nil
}

func (a *Agent) ResetVmInLab(ctx context.Context, req *proto.VmRequest) (*proto.StatusResponse, error) {
	l, err := a.EnvPool.GetLabByTag(req.LabTag)
	if err != nil {
		log.Error().Str("labTag", req.LabTag).Err(err).Msg("error getting lab by tag")
		return nil, err
	}

	envTag := strings.Split(l.Tag, "-")[0]
	env, err := a.EnvPool.GetEnv(envTag)
	if err != nil {
		log.Error().Str("envTag", envTag).Msg("error finding finding environment with tag")
		return nil, fmt.Errorf("error finding environment with tag: %s", envTag)
	}

	// In case teamsize is larger than one
	// A connectionIdentifier is required to determine which vm to reset
	if env.EnvConfig.TeamSize > 1 {
		portStr, err := env.Guac.GetPortFromConnectionIdentifier(req.ConnectionIdentifier)
		if err != nil {
			log.Error().Err(err).Msg("error getting port from connection identifier")
			return nil, err
		}

		portInt, _ := strconv.Atoi(portStr)

		log.Debug().Str("port", portStr).Msg("response from GetPortFromConnectionIdentifier")

		// Checking the lab for frontends with the requested port
		// This is to only allow a team to reset a vm within their own lab
		// since the connectionIdentifier is untrusted input

		l.M.Lock()
		defer func() {
			l.M.Unlock()
			if err := state.SaveState(a.EnvPool, a.config.StatePath); err != nil {
				log.Error().Err(err).Msg("error saving state")
			}
		}()
		if frontend, ok := l.Frontends[uint(portInt)]; ok {
			log.Debug().Msgf("frontend from lab frontends: %v", frontend)
			if err := l.ResetVm(ctx, uint(portInt), envTag); err != nil {
				log.Error().Err(err).Msg("error resetting vm")
				return nil, err
			}
			return &proto.StatusResponse{Message: "OK"}, nil
		}

		return nil, errors.New("frontend with that connection identifier not found in lab")
	} else {
		l.M.Lock()
		defer l.M.Unlock()
		for port := range l.Frontends {
			if err := l.ResetVm(ctx, port, envTag); err != nil {
				log.Error().Err(err).Msg("error resetting vm")
				return nil, err
			}
		}
		return &proto.StatusResponse{Message: "OK"}, nil
	}
}

// Shuts down and removes all frontends and containers related to specific lab. Then removes it from the environment's lab map.
func (a *Agent) CloseLab(ctx context.Context, req *proto.CloseLabRequest) (*proto.StatusResponse, error) {
	l, err := a.EnvPool.GetLabByTag(req.LabTag)
	if err != nil {
		log.Error().Str("labTag", req.LabTag).Err(err).Msg("error getting lab by tag")
		return nil, err
	}
	defer func() {
		if err := state.SaveState(a.EnvPool, a.config.StatePath); err != nil {
			log.Error().Err(err).Msg("error saving state")
		}
	}()
	a.workerPool.AddTask(func() {
		l.M.Lock()
		defer l.M.Unlock()
		if err := l.Close(); err != nil {
			log.Error().Err(err).Msg("error closing lab")
		}
	})

	envKey := strings.Split(req.LabTag, "-")
	env, _ := a.EnvPool.GetEnv(envKey[0])

	log.Debug().Str("envKey", envKey[0]).Msg("env for lab")

	a.EnvPool.Envs[envKey[0]].M.Lock()
	delete(a.EnvPool.Envs[envKey[0]].Labs, req.LabTag)
	a.EnvPool.Envs[envKey[0]].M.Unlock()

	if l.IsVPN {
		env.RemoveVpnLabPeers(ctx, req.LabTag)
	}

	return &proto.StatusResponse{Message: "OK"}, nil
}

// GRPc endpoint that adds exercises to an already running lab. It requires the lab tag, and an array of exercise tags.
// It starts by creating the containers needed for the exercise, then it refreshes the DNS and starts the containers afterwards.
// It utilizes a mutex lock to make sure that if anyone tries to run the same GRPc call twice without the first being finished, the second one will wait
func (a *Agent) AddExercisesToLab(ctx context.Context, req *proto.ExerciseRequest) (*proto.StatusResponse, error) {
	l, err := a.EnvPool.GetLabByTag(req.LabTag)
	if err != nil {
		log.Error().Str("labTag", req.LabTag).Err(err).Msg("error getting lab by tag")
		return nil, err
	}

	if l.Type == lab.TypeBeginner {
		return nil, errors.New("cannot add arbitrary exercise to lab of type beginner")
	}

	// Unpack into exercise slice
	var exerConfs []exercise.ExerciseConfig
	for _, e := range req.ExerciseConfigs {
		ex, err := protobufToJson(e)
		if err != nil {
			return nil, err
		}
		estruct := exercise.ExerciseConfig{}
		json.Unmarshal([]byte(ex), &estruct)
		exerConfs = append(exerConfs, estruct)
	}

	defer func() {
		if err := state.SaveState(a.EnvPool, a.config.StatePath); err != nil {
			log.Error().Err(err).Msg("error saving state")
		}
	}()

	// Add exercises to lab
	ctx = context.Background()
	if err := l.AddAndStartExercises(ctx, exerConfs...); err != nil {
		log.Error().Err(err).Msg("error adding and starting exercises")
		return nil, fmt.Errorf("error adding and starting exercises: %v", err)
	}

	// TODO: Need to return host information back to daemon to display to user in case of VPN lab
	return &proto.StatusResponse{Message: "OK"}, nil
}

// Starts a suspended/stopped exercise in a specific lab
func (a *Agent) StartExerciseInLab(ctx context.Context, req *proto.ExerciseRequest) (*proto.StatusResponse, error) {
	l, err := a.EnvPool.GetLabByTag(req.LabTag)
	if err != nil {
		log.Error().Str("labTag", req.LabTag).Err(err).Msg("error getting lab by tag")
		return nil, err
	}

	defer func() {
		if err := state.SaveState(a.EnvPool, a.config.StatePath); err != nil {
			log.Error().Err(err).Msg("error saving state")
		}
	}()

	ctx = context.Background()
	if err := l.StartExercise(ctx, req.Exercise); err != nil {
		return nil, err
	}

	return &proto.StatusResponse{Message: "OK"}, nil
}

// Stops a running exercise for a specific lab
func (a *Agent) StopExerciseInLab(ctx context.Context, req *proto.ExerciseRequest) (*proto.StatusResponse, error) {
	l, err := a.EnvPool.GetLabByTag(req.LabTag)
	if err != nil {
		log.Error().Str("labTag", req.LabTag).Err(err).Msg("error getting lab by tag")
		return nil, err
	}

	defer func() {
		if err := state.SaveState(a.EnvPool, a.config.StatePath); err != nil {
			log.Error().Err(err).Msg("error saving state")
		}
	}()

	ctx = context.Background()
	if err := l.StopExercise(ctx, req.Exercise); err != nil {
		return nil, err
	}

	return &proto.StatusResponse{Message: "OK"}, nil
}

// Recreates and starts an exercise in a specific lab in case it should be having problems of any sorts.
func (a *Agent) ResetExerciseInLab(ctx context.Context, req *proto.ExerciseRequest) (*proto.StatusResponse, error) {
	l, err := a.EnvPool.GetLabByTag(req.LabTag)
	if err != nil {
		log.Error().Str("labTag", req.LabTag).Err(err).Msg("error getting lab by tag")
		return nil, err
	}

	defer func() {
		if err := state.SaveState(a.EnvPool, a.config.StatePath); err != nil {
			log.Error().Err(err).Msg("error saving state")
		}
	}()

	ctx = context.Background()
	if err := l.ResetExercise(ctx, req.Exercise); err != nil {
		log.Error().Err(err).Msg("error resetting exercise")
		return nil, errors.New("error resetting exercise")
	}

	return &proto.StatusResponse{Message: "OK"}, nil
}

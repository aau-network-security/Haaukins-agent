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
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
	"github.com/aau-network-security/haaukins-agent/internal/state"
	"github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/rs/zerolog/log"
)

var (
	vpnIPPool = newIPPoolFromHost()
)

// Creates a new lab environment. Should be called by the daemon when a new event is being created.
// Environments can be advanced or beginner environments.
// Advanced environments is geared towards regular CTFs where as beginner environments can be used for
// beginner events where the user would just need to press the connect button and a lab would be ready with all challenges running.
func (a *Agent) CreateEnvironment(ctx context.Context, req *proto.CreatEnvRequest) (*proto.StatusResponse, error) {
	// Env for event already exists, Do not start a new guac container
	a.EnvPool.AddStartingEnv(req.EventTag)
	defer func() {
		a.EnvPool.RemoveStartingEnv(req.EventTag)
		if err := state.SaveState(a.EnvPool, a.config.StatePath); err != nil {
			log.Error().Err(err).Msg("error saving state")
		}
	}()
	log.Debug().Msgf("got createEnv request: %v", req)

	if a.EnvPool.DoesEnvExist(req.EventTag) {
		return nil, fmt.Errorf("environment with tag: \"%s\" already exists", req.EventTag)
	}

	// Create a new environment for event if it does not exists
	// Setting up the env config
	var envConf env.EnvConfig
	envConf.Tag = req.EventTag
	envConf.Type = lab.LabType(req.EnvType)
	envConf.WorkerPool = a.workerPool
	envConf.TeamSize = int(req.TeamSize)
	log.Debug().Str("envtype", envConf.Type.String()).Msg("making environment with type")

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
	envConf.LabConf.ExerciseConfs = exerConfs

	frontend := virtual.InstanceConfig{
		Image:    req.Vm.Image,
		MemoryMB: uint(req.Vm.MemoryMB),
		CPU:      req.Vm.Cpu,
	}

	if req.TeamSize == 0 {
		return nil, errors.New("cannot create env with 0 teamsize")
	}
	for i := 0; i < int(req.TeamSize); i++ {
		envConf.LabConf.Frontends = append(envConf.LabConf.Frontends, frontend)
	}

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
	env, err := envConf.NewEnv(ctx)
	if err != nil {
		log.Error().Err(err).Msg("error creating environment")
		vpnIPPool.ReleaseIP(vpnIP)
		return &proto.StatusResponse{Message: "Error creating environment"}, err
	}

	m := &sync.RWMutex{}
	// If it is a beginner event, labs will be created and be available beforehand
	if envConf.Type == lab.TypeBeginner {
		for i := 0; i < int(req.InitialLabs); i++ {
			// Adding lab creation task to taskqueue
			envConf.WorkerPool.AddTask(func() {
				ctx := context.Background()
				log.Debug().Uint8("envStatus", uint8(envConf.Status)).Msg("environment status when starting worker")
				// Make sure that environment is still running before creating lab
				if envConf.Status == environment.StatusClosing || envConf.Status == environment.StatusClosed {
					log.Info().Msg("environment closed before newlab task was taken from queue, canceling...")
					return
				}
				// Creating containers and frontends
				lab, err := envConf.LabConf.NewLab(ctx, false, lab.TypeBeginner, envConf.Tag)
				if err != nil {
					log.Error().Err(err).Str("eventTag", env.EnvConfig.Tag).Msg("error creating new lab")
					return
				}
				// Starting the created containers and frontends
				if err := lab.Start(ctx); err != nil {
					log.Error().Err(err).Str("eventTag", env.EnvConfig.Tag).Msg("error starting new lab")
					return
				}

				if err := env.CreateGuacConn(lab); err != nil {
					log.Error().Err(err).Str("labTag", lab.Tag).Msg("error creating guac connection for lab")
				}

				log.Debug().Uint8("envStatus", uint8(envConf.Status)).Msg("environment status when ending worker")
				// If lab was created while running CloseEnvironment, close the lab
				if envConf.Status == environment.StatusClosing || envConf.Status == environment.StatusClosed {
					log.Info().Msg("environment closed while newlab task was running from queue, closing lab...")
					if err := lab.Close(); err != nil {
						log.Error().Err(err).Msg("error closing lab")
						return
					}
					return
				}
				// Sending lab info to daemon
				// TODO Figure out what exact data should be returned to daemon
				// TODO use new getChallenges function to get challenges for lab to return flag etc.

				newLab := proto.Lab{
					Tag:       lab.Tag,
					EventTag:  envConf.Tag,
					Exercises: lab.GetExercisesInfo(),
					IsVPN:     false,
					GuacCreds: &proto.GuacCreds{
						Username: lab.GuacUsername,
						Password: lab.GuacPassword,
					},
				}
				//a.newLabs = append(a.newLabs, newLab)
				a.newLabs <- newLab
				// Adding lab to environment
				m.Lock()
				env.Labs[lab.Tag] = &lab
				m.Unlock()
				// Should not be removed as it runs in a worker
				if err := state.SaveState(a.EnvPool, a.config.StatePath); err != nil {
					log.Error().Err(err).Msg("error saving state")
				}
			})
		}
	}

	// Start the environment
	if err := env.Start(context.TODO()); err != nil {
		log.Error().Err(err).Msg("error creating environment")
		vpnIPPool.ReleaseIP(vpnIP)
		if err := env.Close(); err != nil {
			log.Error().Err(err).Msg("error closing environment after error creating it")
		}
		return &proto.StatusResponse{Message: "Error creating environment"}, err
	}

	a.EnvPool.AddEnv(env)
	return &proto.StatusResponse{Message: "recieved createLabs request... starting labs"}, nil
}

// Closes environment and attached containers/vms, and removes the environment from the event pool
func (a *Agent) CloseEnvironment(ctx context.Context, req *proto.CloseEnvRequest) (*proto.StatusResponse, error) {
	a.EnvPool.AddClosingEnv(req.EventTag)
	defer func() {
		a.EnvPool.RemoveClosingEnv(req.EventTag)
		if err := state.SaveState(a.EnvPool, a.config.StatePath); err != nil {
			log.Error().Err(err).Msg("error saving state")
		}
	}()

	env, err := a.EnvPool.GetEnv(req.EventTag)
	if err != nil {
		log.Error().Str("envTag", req.EventTag).Msg("error finding finding environment with tag")
		return nil, fmt.Errorf("error finding environment with tag: %s", req.EventTag)
	}

	env.EnvConfig.Status = environment.StatusClosing

	envConf := env.EnvConfig

	vpnIP := strings.ReplaceAll(envConf.VPNAddress, ".240.1/22", "")
	vpnIPPool.ReleaseIP(vpnIP)

	if err := virtual.RemoveEventFolder(string(envConf.Tag)); err != nil {
		log.Warn().Err(err).Msg("error removing event folder")
	}

	if err := env.Close(); err != nil {
		log.Error().Err(err).Msg("error closing environment")
		return nil, fmt.Errorf("error closing environment %v", err)
	}

	env.EnvConfig.Status = environment.StatusClosed

	a.EnvPool.RemoveEnv(envConf.Tag)
	return &proto.StatusResponse{Message: "OK"}, nil
}

// Adds exercises to a beginner environment
// It appends the new exercise configs to the existing lab config within the environment.
// This is used for future labs that may start up.
// Then it adds the exercises to the existing running labs under this environment.
func (a *Agent) AddExercisesToEnv(ctx context.Context, req *proto.ExerciseRequest) (*proto.StatusResponse, error) {
	env, ok := a.EnvPool.Envs[req.EnvTag]
	if !ok {
		log.Error().Str("envTag", req.EnvTag).Msg("error finding finding environment with tag")
		return nil, fmt.Errorf("error finding environment with tag: %s", req.EnvTag)
	}

	if env.EnvConfig.Type == lab.TypeAdvanced {
		return nil, errors.New("you cannot add exercises to advanced typed environments... use AddExercisesToLab as users manage their own exercises")
	}

	env.M.Lock()
	defer func() {
		env.M.Unlock()
		if err := state.SaveState(a.EnvPool, a.config.StatePath); err != nil {
			log.Error().Err(err).Msg("error saving state")
		}
	}()
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
	for _, eConf := range env.EnvConfig.LabConf.ExerciseConfs {
		for _, reqConf := range exerConfs {
			if eConf.Tag == reqConf.Tag {
				return nil, fmt.Errorf("exercise already exists in environment: %s", reqConf.Tag)
			}
		}
	}
	env.EnvConfig.LabConf.ExerciseConfs = append(env.EnvConfig.LabConf.ExerciseConfs, exerConfs...)

	// TODO: Is it a problem to use the workerpool here? Maybe just use a go routine for each lab.
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

// Lists currently running, starting and closing environments.
func (a *Agent) ListEnvironments(ctx context.Context, req *proto.Empty) (*proto.ListEnvResponse, error) {
	return &proto.ListEnvResponse{
		EventTags:         a.EnvPool.GetEnvList(),
		StartingEventTags: a.EnvPool.GetStartingEnvs(),
		ClosingEventTags:  a.EnvPool.GetClosingEnvs(),
	}, nil
}

func getVPNIP() (string, error) {
	// Get VPN IP address from ip pool
	ip, err := vpnIPPool.Get()
	if err != nil {
		return "", err
	}
	return ip, nil
}

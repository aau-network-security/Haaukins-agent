package state

import (
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	environment "github.com/aau-network-security/haaukins-agent/internal/environment"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/exercise"
	wg "github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/vpn"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
	"github.com/aau-network-security/haaukins-agent/internal/worker"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog/log"
)

// Saves the current state of the environment pool to a state.json file.
// Should be called whenever any changes to the environment pool is made
func SaveState(envPool *environment.EnvPool, statePath string) error {
	envPool.M.RLock()
	defer envPool.M.RUnlock()
	state := State{
		Environments: make(map[string]Environment),
	}
	for k, env := range envPool.Envs {
		env.M.RLock()
		envState := makeEnvState(env)
		env.M.RUnlock()
		state.Environments[k] = envState
	}

	jsonState, err := json.Marshal(state)
	if err != nil {
		log.Error().Err(err).Msg("error marshalling state")
		return err
	}

	path := filepath.Join(statePath, "state.json")
	if err := os.WriteFile(path, jsonState, 0644); err != nil {
		return err
	}

	return nil
}

// Resumes from a saves state, which means it reasembles the environment pool in order to restore it across ex. restarts
func ResumeState(vlib *virtual.VboxLibrary, workerPool worker.WorkerPool, statePath string) (*environment.EnvPool, error) {
	state := State{}

	path := filepath.Join(statePath, "state.json")
	stateStr, err := os.ReadFile(path)
	if stateStr == nil || err != nil {
		return nil, nil
	}

	if err := json.Unmarshal(stateStr, &state); err != nil {
		log.Error().Err(err).Msg("error unmarshalling state")
		if e, ok := err.(*json.SyntaxError); ok {
			log.Printf("syntax error at byte offset %d", e.Offset)
		}
		log.Debug().Msgf("state: %q", stateStr)
		return nil, nil
	}

	envPool := &environment.EnvPool{
		M:            &sync.RWMutex{},
		Envs:         make(map[string]*environment.Environment),
		StartingEnvs: make(map[string]bool),
		ClosingEnvs:  make(map[string]bool),
	}
	for k, envState := range state.Environments {
		env, err := convertEnvState(envState, vlib, workerPool)
		if err != nil {
			log.Error().Err(err).Msg("error converting env")
			return nil, err
		}
		envPool.Envs[k] = env
	}

	jsonState, err := json.Marshal(state)
	if err != nil {
		log.Error().Err(err).Msg("error marshalling state")
		return nil, err
	}

	_ = os.WriteFile(path, jsonState, 0644)

	return envPool, nil
}

// Converts the environment state (state.Environment) from the state.json file into the type environment.Environment to be inserted to the environment pool
func convertEnvState(envState Environment, vlib *virtual.VboxLibrary, workerPool worker.WorkerPool) (*environment.Environment, error) {
	env := &environment.Environment{
		M:       &sync.RWMutex{},
		IpRules: envState.IpRules,
		Labs:    make(map[string]*lab.Lab),
	}
	env.EnvConfig = &environment.EnvConfig{
		Tag:             envState.EnvConfig.Tag,
		Type:            envState.EnvConfig.Type,
		VPNAddress:      envState.EnvConfig.VPNAddress,
		VPNEndpointPort: envState.EnvConfig.VPNEndpointPort,
		VpnConfig:       envState.EnvConfig.VpnConfig,
		TeamSize:        envState.EnvConfig.TeamSize,
		WorkerPool:      workerPool,
		LabConf: lab.LabConf{
			Vlib:              vlib,
			Frontends:         envState.EnvConfig.LabConf.Frontends,
			ExerciseConfs:     envState.EnvConfig.LabConf.ExerciseConfs,
			DisabledExercises: envState.EnvConfig.LabConf.DisabledExercises,
		},
		Status: envState.EnvConfig.Status,
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Jar: jar,
	}

	env.Guac = environment.Guacamole{
		Client:     client,
		Token:      envState.Guac.Token,
		Port:       envState.Guac.Port,
		AdminPass:  envState.Guac.AdminPass,
		Containers: envState.Guac.Containers,
	}

	env.IpT = environment.IPTables{
		Sudo:     envState.IpT.Sudo,
		Flags:    envState.IpT.Flags,
		Debug:    env.IpT.Debug,
		ExecFunc: environment.ShellExec,
	}

	env.IpRules = envState.IpRules
	env.IpAddrs = envState.IpAddrs

	wgClient, err := wg.NewGRPCVPNClient(env.EnvConfig.VpnConfig)
	if err != nil {
		log.Error().Err(err).Msg("error connecting to wg server")
		return &environment.Environment{}, err
	}
	env.Wg = wgClient

	env.GuacUserStore = environment.NewGuacUserStore()

	env.Dockerhost = virtual.NewHost()

	for k, l := range envState.Labs {
		ll, err := convertLabState(l, vlib)
		if err != nil {
			log.Error().Err(err).Msg("error converting lab")
			return nil, err
		}
		env.Labs[k] = ll
	}

	return env, nil
}

// For each lab in the environment state, it converts from state.Lab to lab.Lab type
func convertLabState(l Lab, vlib *virtual.VboxLibrary) (*lab.Lab, error) {
	resumedLab := &lab.Lab{
		M:         &sync.RWMutex{},
		Frontends: make(map[uint]lab.FrontendConf),
		Exercises: make(map[string]*exercise.Exercise),
	}

	resumedLab.Tag = l.Tag
	resumedLab.Type = l.Type

	for k, f := range l.Frontends {
		port, _ := strconv.Atoi(k)
		resumedLab.Frontends[uint(port)] = f
	}

	for k, ex := range l.Exercises {
		exTag := &exercise.Exercise{
			ContainerOpts: ex.ContainerOpts,
			VboxOpts:      ex.VboxOpts,
			Tag:           ex.Tag,
			Vlib:          vlib,
			Net:           ex.Net,
			DnsAddr:       ex.DnsAddr,
			DnsRecords:    ex.DnsRecords,
			Ips:           ex.Ips,
		}
		for _, c := range ex.Containers {
			exTag.Machines = append(exTag.Machines, c)
		}
		for _, vm := range ex.Vms {
			exTag.Machines = append(exTag.Machines, vm)
		}
		resumedLab.Exercises[k] = exTag
	}

	resumedLab.ExerciseConfigs = l.ExerciseConfigs
	resumedLab.DisabledExercises = l.DisabledExercises
	resumedLab.DnsRecords = l.DnsRecords
	resumedLab.DockerHost = virtual.NewHost()
	resumedLab.Network = l.Network
	resumedLab.DnsServer = l.DnsServer
	resumedLab.DhcpServer = l.DhcpServer
	resumedLab.DnsAddress = l.DnsAddress
	resumedLab.Vlib = vlib
	resumedLab.IsVPN = l.IsVPN
	resumedLab.GuacUsername = l.GuacUsername
	resumedLab.GuacPassword = l.GuacPassword
	resumedLab.VpnConfs = l.VpnConfs

	return resumedLab, nil
}

// Takes an environment from the environment pool and makes it into a serializable state.Environment object
func makeEnvState(env *environment.Environment) Environment {
	envState := Environment{
		IpRules: make(map[string]environment.IpRules),
		Labs:    make(map[string]Lab),
	}
	envState.EnvConfig = EnvConfig{
		Tag:             env.EnvConfig.Tag,
		Type:            env.EnvConfig.Type,
		VPNAddress:      env.EnvConfig.VPNAddress,
		VPNEndpointPort: env.EnvConfig.VPNEndpointPort,
		VpnConfig:       env.EnvConfig.VpnConfig,
		TeamSize:        env.EnvConfig.TeamSize,
		LabConf: LabConf{
			Frontends:         env.EnvConfig.LabConf.Frontends,
			ExerciseConfs:     env.EnvConfig.LabConf.ExerciseConfs,
			DisabledExercises: env.EnvConfig.LabConf.DisabledExercises,
		},
		Status: env.EnvConfig.Status,
	}

	envState.Guac = Guacamole{
		Token:      env.Guac.Token,
		Port:       env.Guac.Port,
		AdminPass:  env.Guac.AdminPass,
		Containers: make(map[string]*virtual.Container),
	}

	for k, c := range env.Guac.Containers {
		envState.Guac.Containers[k] = c
	}

	envState.IpAddrs = env.IpAddrs
	envState.IpRules = env.IpRules
	envState.IpT = IPTables{
		Sudo:  env.IpT.Sudo,
		Flags: env.IpT.Flags,
		Debug: env.IpT.Debug,
	}
	for k, l := range env.Labs {
		l.M.RLock()
		labState := makeLabState(l)
		l.M.RUnlock()
		envState.Labs[k] = labState
	}
	return envState
}

// Takes a lab from an environment in the environment pool and makes it into a serializable state.Lab object
func makeLabState(l *lab.Lab) Lab {
	labState := Lab{
		Frontends: make(map[string]lab.FrontendConf),
		Exercises: make(map[string]Exercise),
	}
	labState.Tag = l.Tag
	labState.Type = l.Type

	for k, f := range l.Frontends {
		labState.Frontends[strconv.Itoa(int(k))] = f
	}

	for k, ex := range l.Exercises {
		exTag := Exercise{
			ContainerOpts: ex.ContainerOpts,
			VboxOpts:      ex.VboxOpts,
			Tag:           ex.Tag,
			Net:           ex.Net,
			DnsAddr:       ex.DnsAddr,
			DnsRecords:    ex.DnsRecords,
			Ips:           ex.Ips,
		}
		for _, m := range ex.Machines {
			c, cok := m.(*virtual.Container)
			vm, vmok := m.(*virtual.Vm)
			if cok {
				exTag.Containers = append(exTag.Containers, c)
			} else if vmok {
				exTag.Vms = append(exTag.Vms, vm)
			}
		}
		labState.Exercises[k] = exTag
	}

	labState.ExerciseConfigs = l.ExerciseConfigs
	labState.DisabledExercises = l.DisabledExercises
	labState.DnsRecords = l.DnsRecords
	labState.Network = l.Network
	labState.DnsServer = l.DnsServer
	labState.DhcpServer = l.DhcpServer
	labState.DnsAddress = l.DnsAddress
	labState.IsVPN = l.IsVPN
	labState.GuacUsername = l.GuacUsername
	labState.GuacPassword = l.GuacPassword
	labState.VpnConfs = l.VpnConfs

	return labState
}

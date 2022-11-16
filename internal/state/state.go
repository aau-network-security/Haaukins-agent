package state

import (
	"net/http"
	"net/http/cookiejar"
	"os"
	"strconv"
	"sync"

	environment "github.com/aau-network-security/haaukins-agent/internal/environment"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/exercise"
	wg "github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/vpn"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
	"github.com/aau-network-security/haaukins-agent/internal/worker"
	"github.com/go-redis/redis"
	"github.com/goccy/go-json"
	"github.com/nitishm/go-rejson"
	"github.com/rs/zerolog/log"
)

func (cache *RedisCache) getClient() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     cache.Host,
		Password: "",
		DB:       cache.DB,
	})
}

func (cache *RedisCache) SaveState(envPool *environment.EnvPool) error {
	client := cache.getClient()
	rh := rejson.NewReJSONHandler()
	rh.SetGoRedisClient(client)
	state := State{
		Environments: make(map[string]Environment),
	}
	for k, env := range envPool.Envs {
		envState := makeEnvState(env)
		state.Environments[k] = envState
	}

	jsonState, err := json.Marshal(state)
	if err != nil {
		log.Error().Err(err).Msg("error marshalling state")
		return err
	}

	_ = os.WriteFile("data/state.json", jsonState, 0644)

	if _, err := rh.JSONSet("state", ".", state); err != nil {
		log.Error().Err(err).Msg("error setting state in redis")
		return err
	}

	return nil
}

func (cache *RedisCache) ResumeState(vlib *virtual.VboxLibrary, workerPool worker.WorkerPool) (*environment.EnvPool, error) {
	client := cache.getClient()
	rh := rejson.NewReJSONHandler()
	rh.SetGoRedisClient(client)

	state := State{}

	stateStr, err := rh.JSONGet("state", ".")
	if stateStr == nil {
		return nil, nil
	}
	if err := json.Unmarshal(stateStr.([]byte), &state); err != nil {
		log.Error().Err(err).Msg("error unmarshalling state")
		if e, ok := err.(*json.SyntaxError); ok {
			log.Printf("syntax error at byte offset %d", e.Offset)
		}
		log.Debug().Msgf("state: %q", stateStr)
		return nil, nil
	}

	envPool := &environment.EnvPool{
		M:    &sync.RWMutex{},
		Envs: make(map[string]*environment.Environment),
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

	_ = os.WriteFile("data/state2.json", jsonState, 0644)

	return envPool, nil
}

// TODO: end by defining the return value instead
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
	log.Debug().Uint("port", envState.Guac.Port).Msg("port after resuming state")
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

func convertLabState(l Lab, vlib *virtual.VboxLibrary) (*lab.Lab, error) {
	resumedLab := &lab.Lab{
		M:         &sync.RWMutex{},
		Frontends: make(map[uint]lab.FrontendConf),
		ExTags:    make(map[string]*exercise.Exercise),
	}

	resumedLab.Tag = l.Tag
	resumedLab.Type = l.Type

	for k, f := range l.Frontends {
		port, _ := strconv.Atoi(k)
		resumedLab.Frontends[uint(port)] = f
	}

	for k, ex := range l.ExTags {
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
		resumedLab.ExTags[k] = exTag
	}

	for _, ex := range l.Exercises {
		exercise := &exercise.Exercise{
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
			exercise.Machines = append(exercise.Machines, c)
		}
		for _, vm := range ex.Vms {
			exercise.Machines = append(exercise.Machines, vm)
		}
		resumedLab.Exercises = append(resumedLab.Exercises, exercise)
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

	return resumedLab, nil
}

// TODO: Make functions to assemble the state based on the environmentPool
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
		labState := makeLabState(l)
		envState.Labs[k] = labState
	}
	return envState
}

func makeLabState(l *lab.Lab) Lab {
	labState := Lab{
		Frontends: make(map[string]lab.FrontendConf),
		ExTags:    make(map[string]Exercise),
	}
	labState.Tag = l.Tag
	labState.Type = l.Type

	for k, f := range l.Frontends {
		labState.Frontends[strconv.Itoa(int(k))] = f
	}

	for k, ex := range l.ExTags {
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
		labState.ExTags[k] = exTag
	}

	for _, ex := range l.Exercises {
		exercise := Exercise{
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
				exercise.Containers = append(exercise.Containers, c)
			} else if vmok {
				exercise.Vms = append(exercise.Vms, vm)
			}
		}
		labState.Exercises = append(labState.Exercises, exercise)
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

	return labState
}

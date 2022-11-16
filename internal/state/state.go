package state

import (
	"os"
	"strconv"

	environment "github.com/aau-network-security/haaukins-agent/internal/environment"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
	docker "github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual/docker"
	"github.com/go-redis/redis"
	"github.com/goccy/go-json"
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

	client.Set("state", string(jsonState), 0)
	_ = os.WriteFile("data/test.json", jsonState, 0644)
	return nil
}

func (cache *RedisCache) ResumeState() (*State, error) {

	return nil, nil
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
	}

	envState.Guac = Guacamole{
		Token:      env.Guac.Token,
		Port:       env.Guac.Port,
		AdminPass:  env.Guac.AdminPass,
		Containers: make(map[string]docker.Container),
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
			Machines:      ex.Machines,
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
			Machines:      ex.Machines,
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

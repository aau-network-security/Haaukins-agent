package lab

import (
	"context"
	"fmt"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/exercise"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/dns"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual/docker"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual/vbox"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const defaultImageMEMMB = 4096

// TODO Add start function in here instaed
// Creates and starts a new virtual lab
func (lc *LabConf) NewLab(ctx context.Context, isVPN bool, eventTag string, envLabs *map[string]Lab) (Lab, error) {
	lab := Lab{
		ExTags: make(map[string]*exercise.Exercise),
		Vlib:   lc.Vlib,
	}

	// Create lab network
	if err := lab.CreateNetwork(ctx, isVPN); err != nil {
		return Lab{}, err
	}

	// Add exercises to new lab
	if err := lab.AddExercises(ctx, lc.ExerciseConfs...); err != nil {
		return Lab{}, fmt.Errorf("error adding exercises to lab: %v", err)
	}

	lab.DockerHost = docker.NewHost()
	lab.Frontends = map[uint]FrontendConf{}
	// Generate unique tag for lab
	lab.Tag = generateTag(eventTag)

	// Configure and add frontends to lab
	for _, f := range lc.Frontends {
		port := virtual.GetAvailablePort()
		if _, err := lab.addFrontend(ctx, f, port); err != nil {
			return Lab{}, err
		}
	}
	// TODO start lab here as well

	return lab, nil
}

// CreateNetwork network
func (l *Lab) CreateNetwork(ctx context.Context, isVPN bool) error {
	network, err := docker.NewNetwork(isVPN)
	if err != nil {
		return fmt.Errorf("docker new network err %v", err)
	}
	l.Network = network
	l.Network.SetIsVPN(isVPN)
	l.DnsAddress = l.Network.FormatIP(dns.PreferedIP)
	return nil
}

func (l *Lab) addFrontend(ctx context.Context, conf vbox.InstanceConfig, rdpPort uint) (vbox.VM, error) {
	hostIp, err := l.DockerHost.GetDockerHostIP()
	if err != nil {
		return nil, err
	}
	var mem uint
	if conf.MemoryMB <= 0 || conf.MemoryMB < defaultImageMEMMB/2 {
		log.Debug().Msgf("Memory cannot be smaller or equal to zero or less than [ %d ], setting it to default value [ %d ] ", defaultImageMEMMB/2, defaultImageMEMMB)
		mem = defaultImageMEMMB
		log.Warn().
			Uint("memory", conf.MemoryMB).
			Str("image", conf.Image).
			Msgf(" Image does not have proper memory value setting it to %d  ", defaultImageMEMMB)
	} else {
		mem = conf.MemoryMB
	}
	vm, err := l.Vlib.GetCopy(
		ctx,
		conf,
		vbox.SetBridge(l.Network.Interface()),
		vbox.SetLocalRDP(hostIp, rdpPort),
		vbox.SetRAM(mem),
	)
	if err != nil {
		return nil, err
	}

	l.Frontends[rdpPort] = FrontendConf{
		vm:   vm,
		conf: conf,
	}

	log.Debug().Msgf("Created lab frontend on port %d", rdpPort)

	return vm, nil
}

//prepends a uuid to the eventTag
func generateTag(eventTag string) string {
	id := uuid.New()
	return fmt.Sprintf("%s-%s", eventTag, id)
}

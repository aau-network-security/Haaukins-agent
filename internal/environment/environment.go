package environment

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
	wg "github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/vpn"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual/docker"
	"github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/rs/zerolog/log"
)

var (
	VPNPortmin = 5000
	VPNPortmax = 6000
)

func (ec *EnvConfig) NewEnv(ctx context.Context, newLabs chan proto.Lab, initialLabs int32) (Environment, error) {
	// Make worker work
	guac, err := NewGuac(ctx, ec.Tag)
	if err != nil {
		log.Error().Err(err).Msg("error creating new guacamole")
		return Environment{}, err
	}
	// Getting wireguard client from config
	wgClient, err := wg.NewGRPCVPNClient(ec.VpnConfig)
	if err != nil {
		log.Error().Err(err).Msg("error connecting to wg server")
		return Environment{}, err
	}

	ipT := IPTables{
		sudo:     true,
		execFunc: shellExec,
	}

	dockerHost := docker.NewHost()

	var eventVPNIPs []int

	// TODO Make dynamic based on amount of users on a team
	ipAddrs := makeRange(2, 254)
	for i := 0; i < 4; i++ {
		eventVPNIPs = append(eventVPNIPs, ipAddrs...)
	}

	env := Environment{
		M:             &sync.RWMutex{},
		EnvConfig:     ec,
		Guac:          guac,
		IpAddrs:       eventVPNIPs,
		Labs:          map[string]*lab.Lab{},
		GuacUserStore: NewGuacUserStore(),
		Wg:            wgClient,
		Dockerhost:    dockerHost,
		IpT:           ipT,
		IpRules:       map[string]IpRules{},
	}

	m := &sync.RWMutex{}
	// If it is a beginner event, labs will be created and be available beforehand
	// TODO: add more vms based on amount of users on a team
	if ec.Type == lab.TypeBeginner {
		for i := 0; i < int(initialLabs); i++ {
			// Adding lab creation task to taskqueue
			ec.WorkerPool.AddTask(func() {
				ctx := context.Background()
				log.Debug().Uint8("envStatus", uint8(ec.Status)).Msg("environment status when starting worker")
				// Make sure that environment is still running before creating lab
				if ec.Status == StatusClosing || ec.Status == StatusClosed {
					log.Info().Msg("environment closed before newlab task was taken from queue, canceling...")
					return
				}
				// Creating containers and frontends
				lab, err := ec.LabConf.NewLab(ctx, false, lab.TypeBeginner, ec.Tag)
				if err != nil {
					log.Error().Err(err).Str("eventTag", env.EnvConfig.Tag).Msg("error creating new lab")
					return
				}
				// Starting the created containers and frontends
				if err := lab.Start(ctx); err != nil {
					log.Error().Err(err).Str("eventTag", env.EnvConfig.Tag).Msg("error starting new lab")
					return
				}

				log.Debug().Uint8("envStatus", uint8(ec.Status)).Msg("environment status when ending worker")
				// If lab was created while running CloseEnvironment, close the lab
				if ec.Status == StatusClosing || ec.Status == StatusClosed {
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
					Tag:      lab.Tag,
					EventTag: ec.Tag,
					IsVPN:    false,
				}
				newLabs <- newLab
				// Adding lab to environment
				m.Lock()
				env.Labs[lab.Tag] = &lab
				m.Unlock()

			})
		}
	}

	return env, nil
}

func (env *Environment) Start(ctx context.Context) error {
	// Just for Logging purposes
	var frontendNames []string
	for _, f := range env.EnvConfig.LabConf.Frontends {
		frontendNames = append(frontendNames, f.Image)
	}
	log.Info().
		Str("Tag", env.EnvConfig.Tag).
		Strs("Frontends", frontendNames).
		Msg("starting environment")

	// Getting port to listen on for VPN for the environment
	port := rand.Intn(VPNPortmax-VPNPortmin) + VPNPortmin
	for checkPort(port) {
		port = rand.Intn(VPNPortmax-VPNPortmin) + VPNPortmin
	}
	env.EnvConfig.VPNEndpointPort = port

	// Initializing wireguard for the port
	log.Info().Int("port", port).Msg("initializing VPN endpoinrt on port")
	_, err := env.Wg.InitializeI(context.Background(), &wg.IReq{
		Address:    env.EnvConfig.VPNAddress,
		ListenPort: uint32(port),
		SaveConfig: true,
		Eth:        "eth0",
		IName:      string(env.EnvConfig.Tag),
	})
	if err != nil {
		// Continue without vpn if err is present
		// TODO If vpn is for some reason not initialized, it should be possible to try to reininialize for this specific agent and environment
		log.Error().Err(err).Msg("error initializing vpn endpoint... \n continueing wihout, reininialize from admin webclient")
	}

	// Start the guac containers
	if err := env.Guac.Start(ctx); err != nil {
		log.Error().Err(err).Msg("error starting guac")
		return errors.New("error while starting guac")
	}

	env.EnvConfig.Status = StatusRunning
	return nil
}

// Closes environment including removing all related containers, and vpn configs
func (env *Environment) Close() error {
	env.M.Lock()
	defer env.M.Unlock()

	env.Guac.Close()

	var wg sync.WaitGroup
	for _, l := range env.Labs {
		wg.Add(1)
		go func(c io.Closer) {
			if err := c.Close(); err != nil {
				log.Warn().Msgf("error while closing event '%s': %s", env.EnvConfig.Tag, err)
			}
			defer wg.Done()
		}(l)
	}

	env.removeVPNConfs()
	env.removeIPTableRules()
	return nil
}

func (env *Environment) removeIPTableRules() {
	for tid, ipR := range env.IpRules {
		log.Debug().Str("Team ID ", tid).Msgf("iptables are removing... ")
		env.IpT.removeRejectRule(ipR.Labsubnet)
		env.IpT.removeStateRule(ipR.Labsubnet)
		env.IpT.removeAcceptRule(ipR.Labsubnet, ipR.VpnIps)
	}
}

func (env *Environment) removeVPNConfs() {
	envTag := env.EnvConfig.Tag
	log.Debug().Msgf("Closing VPN connection for event %s", envTag)

	resp, err := env.Wg.ManageNIC(context.Background(), &wg.ManageNICReq{Cmd: "down", Nic: envTag})
	if err != nil {
		log.Error().Msgf("Error when disabling VPN connection for event %s", envTag)

	}
	if resp != nil {
		log.Info().Str("Message", resp.Message).Msgf("VPN connection is closed for event %s ", envTag)
	}
	//removeVPNConfigs removes all generated config files when Haaukins is stopped
	if err := removeVPNConfigs(env.EnvConfig.VpnConfig.Dir + "/" + envTag + "*"); err != nil {
		log.Error().Msgf("Error happened on deleting VPN configuration files for event %s on host  %v", envTag, err)
	}
}

func removeVPNConfigs(confFile string) error {
	log.Info().Msgf("Cleaning up VPN configuration files with following pattern { %s }", confFile)
	files, err := filepath.Glob(confFile)
	if err != nil {
		panic(err)
	}
	for _, f := range files {
		if err := os.Remove(f); err != nil {
			log.Error().Msgf("Error removing file with name %s", f)
		}
	}
	return err
}

func makeRange(min, max int) []int {
	a := make([]int, max-min+1)
	for i := range a {
		a[i] = min + i
	}
	return a
}

// Checks if port is already allocated or not
func checkPort(port int) bool {
	portAllocated := fmt.Sprintf(":%d", port)
	// ensure that VPN port is free to allocate
	conn, _ := net.DialTimeout("tcp", portAllocated, time.Second)
	if conn != nil {
		_ = conn.Close()
		fmt.Printf("Checking VPN port %s\n", portAllocated)
		// true means port is already allocated
		return true
	}
	return false
}

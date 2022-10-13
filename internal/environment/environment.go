package environment

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
	wg "github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/vpn"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual/docker"
	"github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/rs/zerolog/log"
)

var (
	VPNPortmin   = 5000
	VPNPortmax   = 6000
	BeginnerType = 0 // Starts all labs so they are ready for the event
	AdvancedType = 1 // Only starts lab dependencies such as guac and VPN
)

// TODO: Restructure folder structure, to be hierarchical
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
		EnvConfig:     *ec,
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
	if ec.Type == BeginnerType {
		for i := 0; i < int(initialLabs); i++ {
			// Adding lab creation task to taskqueue
			ec.WorkerPool.AddTask(func() {
				ctx := context.Background()
				// Creating containers and frontends
				lab, err := ec.LabConf.NewLab(ctx, false, BeginnerType, ec.Tag)
				if err != nil {
					log.Error().Err(err).Str("eventTag", env.EnvConfig.Tag).Msg("error creating new lab")
					return
				}
				// Starting the created containers and frontends
				if err := lab.Start(ctx); err != nil {
					log.Error().Err(err).Str("eventTag", env.EnvConfig.Tag).Msg("error starting new lab")
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
	return nil
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

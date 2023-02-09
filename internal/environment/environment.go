package environment

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	wgproto "github.com/aau-network-security/gwireguard/proto" //v1.0.3
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
	wg "github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/vpn"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
	"github.com/rs/zerolog/log"
)

var (
	VPNPortmin = 5000
	VPNPortmax = 6000
)

func (ec *EnvConfig) NewEnv(ctx context.Context) (*Environment, error) {
	// Make worker work
	guac, err := NewGuac(ctx, ec.Tag)
	if err != nil {
		log.Error().Err(err).Msg("error creating new guacamole")
		return nil, err
	}
	// Getting wireguard client from config
	wgClient, err := wg.NewGRPCVPNClient(ec.VpnConfig)
	if err != nil {
		log.Error().Err(err).Msg("error connecting to wg server")
		return nil, err
	}

	ipT := IPTables{
		Sudo:     true,
		ExecFunc: ShellExec,
	}

	dockerHost := virtual.NewHost()

	var eventVPNIPs []int

	// TODO Make dynamic based on amount of users on a team
	ipAddrs := makeRange(2, 254)
	for i := 0; i < 4; i++ {
		eventVPNIPs = append(eventVPNIPs, ipAddrs...)
	}

	env := &Environment{
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
	_, err := env.Wg.InitializeI(context.Background(), &wgproto.IReq{
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
		env.IpT.RemoveRejectRule(ipR.Labsubnet)
		env.IpT.RemoveStateRule(ipR.Labsubnet)
		env.IpT.RemoveAcceptRule(ipR.Labsubnet, ipR.VpnIps)
	}
}

func (env *Environment) removeVPNConfs() {
	envTag := env.EnvConfig.Tag
	log.Debug().Msgf("Closing VPN connection for event %s", envTag)

	resp, err := env.Wg.ManageNIC(context.Background(), &wgproto.ManageNICReq{Cmd: "down", Nic: envTag})
	if err != nil {
		log.Error().Err(err).Msgf("Error when disabling VPN connection for event %s", envTag)
		return
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

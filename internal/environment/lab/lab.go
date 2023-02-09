package lab

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"

	wgproto "github.com/aau-network-security/gwireguard/proto" //v1.0.3
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/exercise"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/dhcp"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/dns"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
	"github.com/google/uuid"
	"github.com/hashicorp/go-multierror"
	"github.com/rs/zerolog/log"
)

const defaultImageMEMMB = 4096

type LabType uint32

const (
	// LabType
	TypeBeginner LabType = iota
	TypeAdvanced
)

const (
	vpnInfo          = "https://gitlab.com/-/snippets/2096681/raw/master/instructions.txt"
	installWireguard = "https://gitlab.com/-/snippets/2102002/raw/master/install_wireguard.sh"
	connectWireguard = "https://gitlab.com/-/snippets/2102000/raw/master/connectwireguard.py"
)

func (lType LabType) String() string {
	switch lType {
	case TypeBeginner:
		return "beginner"
	case TypeAdvanced:
		return "advanced"
	}

	log.Error().Msg("type did not match any existing labType")
	return ""
}

// TODO Add comments to remaining functions

// Creates and starts a new virtual lab
func (lc *LabConf) NewLab(ctx context.Context, isVPN bool, labType LabType, eventTag string) (Lab, error) {
	lab := Lab{
		M:               &sync.RWMutex{},
		Exercises:       make(map[string]*exercise.Exercise),
		Vlib:            lc.Vlib,
		ExerciseConfigs: lc.ExerciseConfs,
		GuacUsername:    uuid.New().String()[0:8],
		GuacPassword:    uuid.New().String()[0:8],
		IsVPN:           isVPN,
	}

	// Create lab network
	if err := lab.CreateNetwork(ctx, isVPN); err != nil {
		return Lab{}, fmt.Errorf("error creating network for lab: %v", err)
	}

	// If labtype is beginner lab, ready all exercises from the start
	if labType == TypeBeginner {
		// Add exercises to new lab
		if err := lab.AddExercises(ctx, lc.ExerciseConfs...); err != nil {
			return Lab{}, fmt.Errorf("error adding exercises to lab: %v", err)
		}
	}

	lab.DockerHost = virtual.NewHost()

	// Generate unique tag for lab
	lab.Tag = generateTag(eventTag)
	lab.Type = labType

	// If not a VPN lab
	if !isVPN {
		// Configure and add frontends to lab
		lab.Frontends = map[uint]FrontendConf{}
		for _, f := range lc.Frontends {
			port := virtual.GetAvailablePort()
			if _, err := lab.addFrontend(ctx, f, port); err != nil {
				return Lab{}, err
			}
		}
	}

	return lab, nil
}

func (l *Lab) Start(ctx context.Context) error {
	if err := l.RefreshDNS(ctx); err != nil {
		log.Error().Err(err).Msg("error refreshing dns")
		return err
	}

	var err error
	l.DhcpServer, err = dhcp.New(l.Network.FormatIP)
	if err != nil {
		log.Error().Err(err).Msg("error creating dhcpserver")
		return err
	}

	if err := l.DhcpServer.Run(ctx); err != nil {
		log.Error().Err(err).Msg("error running dhcpserver")
		return err
	}

	if _, err := l.Network.Connect(l.DhcpServer.Container(), 2); err != nil {
		return err
	}
	var res error
	var wg sync.WaitGroup
	for _, ex := range l.Exercises {
		wg.Add(1)
		go func(e *exercise.Exercise) {
			if err := e.Start(ctx); err != nil {
				res = multierror.Append(res, err)
			}
			wg.Done()
		}(ex)
	}
	wg.Wait()
	if res != nil {
		return res
	}

	for _, fconf := range l.Frontends {
		if err := fconf.Vm.Start(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (l *Lab) Close() error {
	var wg sync.WaitGroup
	for _, lab := range l.Frontends {
		wg.Add(1)
		go func(vm *virtual.Vm) {
			// closing VMs....
			defer wg.Done()
			if err := vm.Close(); err != nil {
				log.Error().Msgf("Error on Close function in lab.go %s", err)
			}
		}(lab.Vm)
	}
	wg.Add(1)
	go func() {
		// closing environment containers...
		defer wg.Done()
		// if err := environment.Close(); err != nil {
		// 	log.Error().Msgf("Error while closing environment containers %s", err)
		// }
		var closers []io.Closer

		if l.DhcpServer != nil {
			closers = append(closers, l.DhcpServer)
		}

		if l.DnsServer != nil {
			closers = append(closers, l.DnsServer)
		}

		for _, e := range l.Exercises {
			closers = append(closers, e)
		}

		for _, closer := range closers {
			wg.Add(1)
			go func(c io.Closer) {
				if err := c.Close(); err != nil {
					log.Error().Err(err).Msg("error while closing lab")
				}
				wg.Done()
			}(closer)
		}

	}()
	wg.Wait()

	if err := l.Network.Close(); err != nil {
		log.Error().Err(err).Msg("error while closing network for lab")
	}
	return nil
}

func (l *Lab) RefreshDNS(ctx context.Context) error {

	if l.DnsServer != nil {
		if err := l.DnsServer.Close(); err != nil {
			return err
		}
	}
	var rrSet []dns.RR
	for _, e := range l.Exercises {

		for _, record := range e.DnsRecords {
			rrSet = append(rrSet, dns.RR{Name: record.Name, Type: record.Type, RData: record.RData})
		}
	}

	serv, err := dns.New(rrSet)
	if err != nil {
		return err
	}
	l.DnsServer = serv

	if err := l.DnsServer.Run(ctx); err != nil {
		return err
	}

	if _, err := l.Network.Connect(l.DnsServer.Container(), dns.PreferedIP); err != nil {
		return err
	}

	return nil
}

// CreateNetwork network
func (l *Lab) CreateNetwork(ctx context.Context, isVPN bool) error {
	network, err := virtual.NewNetwork(isVPN)
	if err != nil {
		return fmt.Errorf("docker new network err %v", err)
	}
	l.Network = network
	l.Network.SetIsVPN(isVPN)
	l.DnsAddress = l.Network.FormatIP(dns.PreferedIP)
	return nil
}

func (l *Lab) addFrontend(ctx context.Context, conf virtual.InstanceConfig, rdpPort uint) (*virtual.Vm, error) {
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
		virtual.SetBridge(l.Network.Interface()),
		virtual.SetLocalRDP(hostIp, rdpPort),
		virtual.SetRAM(mem),
	)
	if err != nil {
		return nil, err
	}

	l.Frontends[rdpPort] = FrontendConf{
		Vm:   vm,
		Conf: conf,
	}

	log.Debug().Msgf("Created lab frontend on port %d", rdpPort)

	return vm, nil
}

// Get a list of ports for the VMs running in the lab
func (l *Lab) RdpConnPorts() []uint {
	var ports []uint
	for p := range l.Frontends {
		ports = append(ports, p)
	}

	return ports
}

// Get a list of instance information for the VMs and exercises running in the lab
func (l *Lab) InstanceInfo() []virtual.InstanceInfo {
	var instances []virtual.InstanceInfo
	for _, fconf := range l.Frontends {
		instances = append(instances, fconf.Vm.Info())
	}
	for _, e := range l.Exercises {
		instances = append(instances, e.InstanceInfo()...)
	}
	return instances
}

// prepends a uuid to the eventTag
func generateTag(eventTag string) string {
	id := uuid.New()
	return fmt.Sprintf("%s-%s", eventTag, id)
}

func getDNSRecords(records []*DNSRecord) []string {
	var hosts []string
	for _, r := range records {
		for ip, arecord := range r.Record {
			hosts = append(hosts, fmt.Sprintf("%s \t %s", ip, arecord))
		}
	}
	return hosts
}

type VpnConfig struct {
	Host            string
	VpnAddress      string
	VPNEndpointPort int
	IpAddresses     []int
}

func (lab *Lab) CreateVPNConn(wgClient wgproto.WireguardClient, envTag string, vpnConfig VpnConfig) ([]string, []string, error) {
	var labConfigFiles []string
	lowBound := 240
	upperBound := 244
	ctx := context.Background()
	var vpnIPs []string
	vpnInstructions := getContent(vpnInfo)
	// var hosts string
	// for _, r := range lab.DnsRecords {
	// 	for ip, arecord := range r.Record {
	// 		hosts += fmt.Sprintf("# %s \t %s \n", ip, arecord)
	// 	}

	// }
	//labSubnet := fmt.Sprintf("%s/24", lab.Network.Subnet)
	// random.random.240.1/22
	subnet := vpnConfig.VpnAddress

	// retrieve domain from configuration file
	endpoint := fmt.Sprintf("%s.%s:%d", envTag, vpnConfig.Host, vpnConfig.VPNEndpointPort)

	// get public key of server
	log.Info().Msg("Getting server public key...")
	serverPubKey, err := wgClient.GetPublicKey(ctx, &wgproto.PubKeyReq{PubKeyName: envTag, PrivKeyName: envTag})
	if err != nil {
		return []string{}, []string{}, err
	}

	// create 4 different config file for 1 user
	for i := lowBound; i < upperBound; i++ {

		// generate client privatekey
		ipAddr := pop(&vpnConfig.IpAddresses)

		log.Info().Msgf("Generating privatekey for lab %s", envTag+"_"+lab.Tag)
		_, err = wgClient.GenPrivateKey(ctx, &wgproto.PrivKeyReq{PrivateKeyName: envTag + "_" + lab.Tag + "_" + strconv.Itoa(ipAddr)})
		if err != nil {
			return []string{}, []string{}, err
		}

		// generate client public key
		log.Info().Msgf("Generating public key for lab %s", envTag+"_"+lab.Tag+"_"+strconv.Itoa(ipAddr))
		_, err = wgClient.GenPublicKey(ctx, &wgproto.PubKeyReq{PubKeyName: envTag + "_" + lab.Tag + "_" + strconv.Itoa(ipAddr), PrivKeyName: envTag + "_" + lab.Tag + "_" + strconv.Itoa(ipAddr)})
		if err != nil {
			return []string{}, []string{}, err
		}
		// get client public key
		log.Info().Msgf("Retrieving public key for lab %s", envTag+"_"+lab.Tag+"_"+strconv.Itoa(ipAddr))
		resp, err := wgClient.GetPublicKey(ctx, &wgproto.PubKeyReq{PubKeyName: envTag + "_" + lab.Tag + "_" + strconv.Itoa(ipAddr)})
		if err != nil {
			log.Error().Msgf("Error on GetPublicKey %v", err)
			return []string{}, []string{}, err
		}

		peerIP := strings.Replace(subnet, "240.1/22", fmt.Sprintf("%d.%d/32", i, ipAddr), 2)
		gwIP := strings.Replace(subnet, "1/22", fmt.Sprintf("1/32"), 1)
		log.Info().Str("NIC", envTag).
			Str("AllowedIPs", peerIP).
			Str("PublicKey ", resp.Message).Msgf("Generating ip address for lab %s, ip address of peer is %s ", lab.Tag, peerIP)
		addPeerResp, err := wgClient.AddPeer(ctx, &wgproto.AddPReq{
			Nic:        envTag,
			AllowedIPs: peerIP,
			PublicKey:  resp.Message,
		})
		if err != nil {
			log.Error().Msgf("Error on adding peer to interface %v", err)
			return []string{}, []string{}, err
		}
		log.Info().Str("Event: ", envTag).
			Str("Lab: ", lab.Tag).Msgf("Message : %s", addPeerResp.Message)
		//get client privatekey
		log.Info().Msgf("Retrieving private key for lab %s", lab.Tag)
		labPrivKey, err := wgClient.GetPrivateKey(ctx, &wgproto.PrivKeyReq{PrivateKeyName: envTag + "_" + lab.Tag + "_" + strconv.Itoa(ipAddr)})
		if err != nil {
			return []string{}, []string{}, err
		}
		log.Info().Msgf("Private key for lab %s is %s ", lab.Tag, labPrivKey.Message)
		log.Info().Msgf("Client configuration is created for server %s", endpoint)
		// creating client configuration file
		clientConfig := fmt.Sprintf(
			`[Interface]
Address = %s
PrivateKey = %s
MTU = 1420
[Peer]
PublicKey = %s
AllowedIps = %s,%s
Endpoint =  %s
PersistentKeepalive = 25

# --------------------------------------------------------------------------
#  YOUR LAB SUBNET IS:  %s 													
# --------------------------------------------------------------------------

######### << USER SCRIPTS >> #####
#  
#	Use following scripts to install wireguard and connect to lab. 
#
#   Install Wireguard: %s 
#  	
#	Connect Event:  %s
#
#   The scripts are automating steps which you do manually. Use them with your responsibility.
#   If you notice outdated information, help us to update it :) 
#
####################

####### SETTING VPN CONFIGURATION #########

%s

`, peerIP, labPrivKey.Message, serverPubKey.Message, lab.DhcpServer.Subnet, gwIP, endpoint, lab.DhcpServer.Subnet, installWireguard, connectWireguard, vpnInstructions)
		labConfigFiles = append(labConfigFiles, clientConfig)
		vpnIPs = append(vpnIPs, peerIP)
	}

	vpnIPs = append(vpnIPs, lab.DhcpServer.Subnet)
	return labConfigFiles, vpnIPs, nil
}

// get page content
func getContent(link string) string {
	res, err := http.Get(link)
	if err != nil {
		log.Debug().Msgf("Error on retrieving link [ %s ] Err: [ %v ]", link, err)
	}
	content, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		log.Debug().Msgf("Read error content [ %s ] Err: [ %v ]", link, err)
	}
	return string(content)
}

// pop function is somehow same with python pop function
func pop(alist *[]int) int {
	f := len(*alist)
	rv := (*alist)[f-1]
	*alist = append((*alist)[:f-1])
	return rv
}

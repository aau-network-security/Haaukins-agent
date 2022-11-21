package state

import (
	env "github.com/aau-network-security/haaukins-agent/internal/environment"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/exercise"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/dhcp"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/dns"
	wg "github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/vpn"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
)

// The state models are somewhat of a copy of the models from the env, lab, exercise packages etc.
// However the models in the state only has values which can be masharled to a json string since alot of the models in the packages holds interfaces, functions etc. which cannot be marshalled.
// So the state variables will be carefully choosen in order to resume the state most effectively.



type Environment struct {
	EnvConfig EnvConfig
	Guac      Guacamole
	IpT       IPTables
	IpRules   map[string]env.IpRules
	IpAddrs   []int
	Labs      map[string]Lab
}

type EnvConfig struct {
	Tag             string
	Type            lab.LabType
	VPNAddress      string
	VPNEndpointPort int
	VpnConfig       wg.WireGuardConfig
	LabConf         LabConf
	Status          env.Status
}

type Lab struct {
	Tag               string
	Type              lab.LabType
	Frontends         map[string]lab.FrontendConf
	Exercises         map[string]Exercise
	ExerciseConfigs   []exercise.ExerciseConfig
	DisabledExercises []string
	DnsRecords        []*lab.DNSRecord
	Network           *virtual.Network
	DnsServer         *dns.Server
	DhcpServer        *dhcp.Server
	DnsAddress        string
	IsVPN             bool
	GuacUsername      string
	GuacPassword      string
}

type LabConf struct {
	Frontends         []virtual.InstanceConfig
	ExerciseConfs     []exercise.ExerciseConfig
	DisabledExercises []string
}

type Exercise struct {
	ContainerOpts []exercise.ContainerOptions
	VboxOpts      []exercise.ExerciseInstanceConfig
	Tag           string
	Net           *virtual.Network
	DnsAddr       string
	DnsRecords    []exercise.RecordConfig
	Ips           []int
	Containers    []*virtual.Container
	Vms           []*virtual.Vm
}

type Network struct {
	Net       virtual.Network
	Subnet    string
	IsVPN     bool
	Connected []string
}

type Vm struct {
	Id      string
	Path    string
	Image   string
	Running bool
}

type Guacamole struct {
	Token      string
	Port       uint
	AdminPass  string
	Containers map[string]*virtual.Container
}

type Container struct {
	Id      string
	Conf    virtual.ContainerConfig
	Network virtual.Network
}

type IPTables struct {
	Sudo  bool
	Flags []string
	Debug bool
}

type State struct {
	Environments map[string]Environment `json:"environments`
}

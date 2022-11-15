package state

import (
	env "github.com/aau-network-security/haaukins-agent/internal/environment"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/exercise"
	wg "github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/vpn"
	dockerHaaukins "github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual/docker"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual/vbox"
	docker "github.com/fsouza/go-dockerclient"
)

// The state models are somewhat of a copy of the models from the env, lab, exercise packages etc.
// However the models in the state only has values which can be masharled to a json string since alot of the models in the packages holds interfaces, functions etc. which cannot be marshalled.
// So the state variables will be carefully choosen in order to resume the state most effectively.

type RedisCache struct {
	Host string
	DB   int
}

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
}

type Lab struct {
	Tag               string
	Type              lab.LabType
	Frontends         map[string]FrontendConf
	ExTags            map[string]Exercise
	Exercises         []Exercise
	ExerciseConfigs   []exercise.ExerciseConfig
	DisabledExercises []string
	DnsRecords        []lab.DNSRecord
	Network           Network
	DnsServer         DnsServer
	DhcpServer        DhcpServer
	DnsAddress        string
	IsVPN             bool
	GuacUsername      string
	GuacPassword      string
}

type LabConf struct {
	Frontends         []vbox.InstanceConfig
	ExerciseConfs     []exercise.ExerciseConfig
	DisabledExercises []string
}

type Exercise struct {
	ContainerOpts []exercise.ContainerOptions
	VboxOpts      []exercise.ExerciseInstanceConfig
	Tag           string
	Net           Network
	DnsAddr       string
	DnsRecords    []exercise.RecordConfig
	Ips           []int
	Vms           []Vm
	Containers    []Container
}

type DnsServer struct {
	Cont     Container
	ConfFile string
}

type DhcpServer struct {
	Cont     Container
	ConfFile string
	Dns      string
	Subnet   string
}

type Network struct {
	Net       docker.Network
	Subnet    string
	IsVPN     bool
	Connected []string
}

type FrontendConf struct {
	vm   Vm
	Conf vbox.InstanceConfig
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
	Containers map[string]Container
}

type Container struct {
	Id      string
	Conf    dockerHaaukins.ContainerConfig
	Network docker.Network
}

type IPTables struct {
	sudo  bool
	flags []string
	debug bool
}

type State struct {
	Environments map[string]Environment `json:"environments`
}

package lab

import (
	"sync"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/exercise"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/dhcp"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/dns"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
)

type Lab struct {
	M                 *sync.RWMutex
	Tag               string
	Type              LabType
	Frontends         map[uint]FrontendConf
	Exercises         map[string]*exercise.Exercise
	ExerciseConfigs   []exercise.ExerciseConfig
	DisabledExercises []string
	DnsRecords        []*DNSRecord
	DockerHost        virtual.Host
	Network           *virtual.Network
	DnsServer         *dns.Server
	DhcpServer        *dhcp.Server
	DnsAddress        string
	Vlib              *virtual.VboxLibrary
	IsVPN             bool
	GuacUsername      string
	GuacPassword      string
	VpnConfs          []string
}

type LabConf struct {
	Vlib              *virtual.VboxLibrary
	Frontends         []virtual.InstanceConfig
	ExerciseConfs     []exercise.ExerciseConfig
	DisabledExercises []string
}

type DNSRecord struct {
	Record map[string]string
}

type FrontendConf struct {
	Vm   *virtual.Vm
	Conf virtual.InstanceConfig
}

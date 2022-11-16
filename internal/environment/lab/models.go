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
	ExTags            map[string]*exercise.Exercise
	Exercises         []*exercise.Exercise
	ExerciseConfigs   []exercise.ExerciseConfig
	DisabledExercises []string
	DnsRecords        []*DNSRecord
	DockerHost        virtual.Host
	Network           virtual.NetworkHandler
	DnsServer         *dns.Server
	DhcpServer        *dhcp.Server
	DnsAddress        string
	Vlib              virtual.VboxLibraryHandler
	IsVPN             bool
	GuacUsername      string
	GuacPassword      string
}

type LabConf struct {
	Vlib              virtual.VboxLibraryHandler
	Frontends         []virtual.InstanceConfig
	ExerciseConfs     []exercise.ExerciseConfig
	DisabledExercises []string
}

type DNSRecord struct {
	Record map[string]string
}

type FrontendConf struct {
	vm   virtual.VmHandler
	conf virtual.InstanceConfig
}

package lab

import (
	"sync"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/exercise"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/dhcp"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/dns"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual/docker"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual/vbox"
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
	DockerHost        docker.Host
	Network           docker.Network
	DnsServer         *dns.Server
	DhcpServer        *dhcp.Server
	DnsAddress        string
	Vlib              vbox.Library
	IsVPN             bool
	GuacUsername      string
	GuacPassword      string
}

type LabConf struct {
	Vlib              vbox.Library
	Frontends         []vbox.InstanceConfig
	ExerciseConfs     []exercise.ExerciseConfig
	DisabledExercises []string
}

type DNSRecord struct {
	Record map[string]string
}

type FrontendConf struct {
	vm   vbox.VM
	conf vbox.InstanceConfig
}

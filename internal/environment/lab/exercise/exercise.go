package exercise

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual/docker"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual/vbox"
)

var (
	DuplicateTagErr = errors.New("Tag already exists")
	MissingTagsErr  = errors.New("No tags, need atleast one tag")
	UnknownTagErr   = errors.New("Unknown tag")
	RegistryLink    = "registry.gitlab.com"
	tagRawRegexp    = `^[a-z0-9][a-z0-9-]*[a-z0-9]$`
	tagRegex        = regexp.MustCompile(tagRawRegexp)
	OvaSuffix       = ".ova"
)

func NewExercise(conf ExerciseConfig, vlib vbox.Library, net docker.Network, dnsAddr string) *Exercise {
	var containerOpts []ContainerOptions
	var vboxOpts []ExerciseInstanceConfig
	var ex *Exercise
	for _, c := range conf.Instance {
		if strings.Contains(c.Image, OvaSuffix) {
			vboxOpts = append(vboxOpts, c)
		} else {
			containerOpts = conf.ContainerOpts()
			break
		}
	}

	if !conf.Static {
		ex = &Exercise{
			ContainerOpts: containerOpts,
			VboxOpts:      vboxOpts,
			Tag:           conf.Tag,
			Vlib:          vlib,
			Net:           net,
			DnsAddr:       dnsAddr,
		}
	} else {
		ex = &Exercise{
			ContainerOpts: containerOpts,
			Tag:           conf.Tag,
		}
	}
	return ex
}

func (e *Exercise) Create(ctx context.Context) error {
	var machines []virtual.Instance
	var newIps []int
	for i, opt := range e.ContainerOpts {
		opt.DockerConf.DNS = []string{e.DnsAddr}
		opt.DockerConf.Labels = map[string]string{
			"hkn": "lab_exercise",
		}

		c, err := CreateContainer(ctx, opt.DockerConf)
		if err != nil {
			return err
		}

		var lastDigit int
		// Example: 216

		if e.Ips != nil {
			// Containers need specific ips
			lastDigit, err = e.Net.Connect(c, e.Ips[i])
			if err != nil {
				return err
			}
		} else {
			// Let network assign ips
			lastDigit, err = e.Net.Connect(c)
			if err != nil {
				return err
			}

			newIps = append(newIps, lastDigit)
		}

		ipaddr := e.Net.FormatIP(lastDigit)
		// Example: 172.16.5.216

		for _, record := range opt.Records {
			if record.RData == "" {
				record.RData = ipaddr
			}
			e.DnsRecords = append(e.DnsRecords, record)
		}

		machines = append(machines, c)
	}

	for _, vboxConf := range e.VboxOpts {
		vmConf := vbox.InstanceConfig{
			Image:    vboxConf.Image,
			CPU:      vboxConf.CPU,
			MemoryMB: vboxConf.MemoryMB,
		}
		vm, err := e.Vlib.GetCopy(
			ctx,
			vmConf,
			vbox.SetBridge(e.Net.Interface()),
		)
		if err != nil {
			return err
		}
		machines = append(machines, vm)
	}

	if e.Ips == nil {
		e.Ips = newIps
	}

	e.Machines = machines

	return nil
}

func CreateContainer(ctx context.Context, conf docker.ContainerConfig) (docker.Container, error) {
	c := docker.NewContainer(conf)
	err := c.Create(ctx)

	return c, err
}

func (e ExerciseConfig) ContainerOpts() []ContainerOptions {
	var opts []ContainerOptions

	for _, conf := range e.Instance {
		var challenges []Challenge
		envVars := make(map[string]string)

		for _, flag := range conf.Flags {
			value := flag.StaticFlag

			// static flag format in exercises file
			//  should obey flag format HKN{*********}
			if value == "" {
				// flag is not static
				value = NewFlag().String()
				envVars[flag.EnvVar] = value
			}

			challenges = append(challenges, Challenge{
				Name:  flag.Name,
				Tag:   flag.Tag,
				Value: value,
			})

		}

		for _, env := range conf.Envs {
			envVars[env.EnvVar] = env.Value
		}

		// docker config

		spec := docker.ContainerConfig{}

		if !e.Static {
			spec = docker.ContainerConfig{
				Image: conf.Image,
				Resources: &docker.Resources{
					MemoryMB: conf.MemoryMB,
					CPU:      conf.CPU,
				},
				EnvVars: envVars,
			}
		}

		opts = append(opts, ContainerOptions{
			DockerConf: spec,
			Records:    conf.Records,
			Challenges: challenges,
		})
	}

	return opts
}

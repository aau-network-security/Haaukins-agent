package exercise

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
	"github.com/hashicorp/go-multierror"
	"github.com/rs/zerolog/log"
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

// TODO add comments
func NewExercise(conf ExerciseConfig, vlib *virtual.VboxLibrary, net *virtual.Network, dnsAddr string) *Exercise {
	var containerOpts []ContainerOptions
	var vboxOpts []ExerciseInstanceConfig
	var ex *Exercise
	for _, c := range conf.Instance {
		if strings.Contains(c.Image, OvaSuffix) {
			vboxOpts = append(vboxOpts, c)
		} else {
			containerOpts = conf.CreateContainerOpts()
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
		vmConf := virtual.InstanceConfig{
			Image:    vboxConf.Image,
			CPU:      vboxConf.CPU,
			MemoryMB: vboxConf.MemoryMB,
		}
		vm, err := e.Vlib.GetCopy(
			ctx,
			vmConf,
			virtual.SetBridge(e.Net.Interface()),
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

func (e *Exercise) Start(ctx context.Context) error {
	var res error
	var wg sync.WaitGroup

	for _, m := range e.Machines {
		wg.Add(1)
		go func(m virtual.Instance) {
			if m.Info().State != virtual.Running {
				if err := m.Start(ctx); err != nil && res == nil {
					res = multierror.Append(res, err)
				}
			}
			wg.Done()
		}(m)
	}
	wg.Wait()

	return res
}

// TODO: Add multierror or go routine
func (e *Exercise) Stop(ctx context.Context) error {
	for _, m := range e.Machines {
		if err := m.Stop(); err != nil {
			return err
		}
	}

	return nil
}

func (e *Exercise) Reset(ctx context.Context) error {
	if err := e.Close(); err != nil {
		return err
	}

	if err := e.Create(ctx); err != nil {
		return err
	}

	if err := e.Start(ctx); err != nil {
		return err
	}
	return nil
}

func (e *Exercise) Close() error {
	var wg sync.WaitGroup

	for _, m := range e.Machines {
		wg.Add(1)
		go func(i virtual.Instance) {
			if err := i.Close(); err != nil {
				log.Warn().Msgf("error while closing exercise: %s", err)
			}
			wg.Done()
		}(m)

	}
	wg.Wait()

	e.Machines = nil
	return nil
}

func CreateContainer(ctx context.Context, conf virtual.ContainerConfig) (*virtual.Container, error) {
	c := virtual.NewContainer(conf)
	err := c.Create(ctx)

	return c, err
}

func (e ExerciseConfig) CreateContainerOpts() []ContainerOptions {
	var opts []ContainerOptions

	for _, conf := range e.Instance {
		var childExercises []ChildExercise
		envVars := make(map[string]string)

		for _, flag := range conf.Flags {
			value := flag.StaticFlag

			// static flag format in exercises file
			//  should obey flag format HKN{*********}
			if value == "" {
				// flag is not static
				value = NewFlag().String()
				if flag.EnvVar != "" {
					envVars[flag.EnvVar] = value
				}
			} else {
				if flag.EnvVar != "" {
					envVars[flag.EnvVar] = value
				}
			}

			childExercises = append(childExercises, ChildExercise{
				Name:  flag.Name,
				Tag:   flag.Tag,
				Value: value,
			})

		}

		for _, env := range conf.Envs {
			envVars[env.EnvVar] = env.Value
		}

		// docker config

		spec := virtual.ContainerConfig{}

		if !e.Static {
			spec = virtual.ContainerConfig{
				Image: conf.Image,
				Resources: &virtual.Resources{
					MemoryMB: conf.MemoryMB,
					CPU:      conf.CPU,
				},
				EnvVars: envVars,
			}
		}

		opts = append(opts, ContainerOptions{
			DockerConf:     spec,
			Records:        conf.Records,
			ChildExercises: childExercises,
		})
	}

	return opts
}

func (e *Exercise) GetChildExercises() []ChildExercise {
	var childExercises []ChildExercise
	for _, opt := range e.ContainerOpts {
		childExercises = append(childExercises, opt.ChildExercises...)
	}

	for _, opt := range e.VboxOpts {
		for _, f := range opt.Flags {
			childExercises = append(childExercises, ChildExercise{
				Name:  f.Name,
				Tag:   f.Tag,
				Value: f.StaticFlag,
			})
		}
	}

	return childExercises
}

func (e *Exercise) InstanceInfo() []virtual.InstanceInfo {
	var instances []virtual.InstanceInfo
	for _, m := range e.Machines {
		instances = append(instances, m.Info())
	}
	return instances
}

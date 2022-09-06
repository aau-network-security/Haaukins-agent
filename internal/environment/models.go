package environment

import (
	"sync"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual/vbox"
)

type EnvPool struct {
	Em   sync.RWMutex
	Envs map[string]Environment
}

type Environment struct {
	Config EnvConfig
	Labs   []lab.Lab
	Stop   chan struct{}
	// Fill out rest when starting to make labs
}

type EnvConfig struct {
	Tag          string
	VPNAddress   string
	FrontendPort uint
	Vlib         vbox.Library
	Frontends    []vbox.InstanceConfig
	Exercises    []lab.Exercise
}

type Category struct {
	Tag            string `json:"tag,omitempty"`
	Name           string `json:"name,omitempty"`
	CatDescription string `json:"catDesc,omitempty"`
}

type Profile struct {
	Name       string       `json:"name,omitempty"`
	Secret     bool         `json:"secret,omitempty"`
	Challenges []PChallenge `json:"challenges,omitempty"`
}

type PChallenge struct {
	Tag  string `json:"tag,omitempty"`
	Name string `json:"name,omitempty"`
}

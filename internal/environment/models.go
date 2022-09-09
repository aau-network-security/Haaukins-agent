package environment

import (
	"sync"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
	wg "github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/vpn"
)

type EnvPool struct {
	Em   sync.RWMutex
	Envs map[string]Environment
}

type Environment struct {
	EnvConfig EnvConfig
	Labs      []lab.Lab
	Stop      chan struct{}
	// Fill out rest when starting to make labs
}

type EnvConfig struct {
	Tag        string
	VPNAddress string
	VpnConfig  wg.WireGuardConfig
	LabConf    lab.LabHost
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

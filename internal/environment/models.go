package environment

import (
	"net/http"
	"sync"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
	wg "github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/vpn"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual/docker"
)

// General environment types
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
	LabConf    lab.LabConf
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

// Guac types
type Guacamole struct {
	Client     *http.Client
	Token      string
	Port       uint
	AdminPass  string
	Containers map[string]docker.Container
}

type createUserAttributes struct {
	Disabled          string  `json:"disabled"`
	Expired           string  `json:"expired"`
	AccessWindowStart string  `json:"access-window-start"`
	AccessWindowEnd   string  `json:"access-window-end"`
	ValidFrom         string  `json:"valid-from"`
	ValidUntil        string  `json:"valid-until"`
	TimeZone          *string `json:"timezone"`
}

type createUserInput struct {
	Username   string               `json:"username"`
	Password   string               `json:"password"`
	Attributes createUserAttributes `json:"attributes"`
}
package exercise

import (
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual/docker"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual/vbox"
)

type Exercise struct {
	ContainerOpts []ContainerOptions
	VboxOpts      []ExerciseInstanceConfig

	Tag  string
	Vlib vbox.Library
	Net  docker.Network

	DnsAddr    string
	DnsRecords []RecordConfig

	Ips      []int
	Machines []virtual.Instance
}

//todo manage the status somehow
type ExerciseConfig struct {
	Tag      string `json:"tag,omitempty"`
	Name     string `json:"name,omitempty"`
	Category string `json:"category,omitempty"`
	Secret   bool   `json:"secret,omitempty"`
	// specifies whether challenge will be on docker/vm or none
	// true: none , false: docker/vm
	Static         bool                     `json:"static,omitempty"`
	Instance       []ExerciseInstanceConfig `json:"instance,omitempty"`
	Status         int                      `json:"status,omitempty"`
	OrgDescription string                   `json:"organizerDescription,omitempty"`
}

type ExerciseInstanceConfig struct {
	Image    string               `json:"image,omitempty"`
	MemoryMB uint                 `json:"memory,omitempty"`
	CPU      float64              `json:"cpu,omitempty"`
	Envs     []EnvVarConfig       `json:"envs,omitempty"`
	Flags    []ChildrenChalConfig `json:"children,omitempty"`
	Records  []RecordConfig       `json:"records,omitempty"`
}

type ContainerOptions struct {
	DockerConf docker.ContainerConfig
	Records    []RecordConfig
	Challenges []Challenge
}

type ChildrenChalConfig struct {
	Tag             string   `json:"tag,omitempty"`
	Name            string   `json:"name,omitempty"`
	EnvVar          string   `json:"envFlag,omitempty"`
	StaticFlag      string   `json:"static,omitempty"`
	Points          uint     `json:"points,omitempty"`
	Category        string   `json:"category,omitempty"`
	TeamDescription string   `json:"teamDescription,omitempty"`
	PreRequisites   []string `json:"prerequisite,omitempty"`
	Outcomes        []string `json:"outcome,omitempty"`
	StaticChallenge bool     `json:"staticChallenge,omitempty"`
}

type EnvVarConfig struct {
	EnvVar string `json:"name,omitempty"`
	Value  string `json:"value,omitempty"`
}

type Challenge struct {
	Name  string //challenge name
	Tag   string //challenge tag
	Value string //challenge flag value
}

type RecordConfig struct {
	Type  string `json:"type,omitempty"`
	Name  string `json:"name,omitempty"`
	RData string `json:"data,omitempty"`
}

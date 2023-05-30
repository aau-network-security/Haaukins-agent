package exercise

import (
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
)

//todo manage exercise status somehow
type Exercise struct {
	ContainerOpts []ContainerOptions
	VboxOpts      []ExerciseInstanceConfig

	Tag  string
	Vlib *virtual.VboxLibrary
	Net  *virtual.Network

	DnsAddr    string
	DnsRecords []RecordConfig

	Ips      []int
	Machines []virtual.Instance
}

type ExerciseConfig struct {
	Tag      string `json:"tag,omitempty"`
	// specifies whether challenge will be on docker/vm or none
	// true: none , false: docker/vm
	Static         bool                     `json:"static,omitempty"`
	Instance       []ExerciseInstanceConfig `json:"instance,omitempty"`
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
	DockerConf     virtual.ContainerConfig
	Records        []RecordConfig
	ChildExercises []ChildExercise
}

type ChildrenChalConfig struct {
	Tag             string   `json:"tag,omitempty"`
	Name            string   `json:"name,omitempty"`
	EnvVar          string   `json:"envFlag,omitempty"`
	StaticFlag      string   `json:"static,omitempty"`
}

type EnvVarConfig struct {
	EnvVar string `json:"name,omitempty"`
	Value  string `json:"value,omitempty"`
}

type ChildExercise struct {
	Name  string //challenge name
	Tag   string //challenge tag
	Value string //challenge flag value
}

type RecordConfig struct {
	Type  string `json:"type,omitempty"`
	Name  string `json:"name,omitempty"`
	RData string `json:"data,omitempty"`
}

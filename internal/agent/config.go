package agent

import (
	dockerclient "github.com/fsouza/go-dockerclient"
)

type Config struct {
	Host               string                           `yaml:"host"`
	GrpcPort           uint                             `yaml:"grpcPort"`
	ProxyPort          uint                             `yaml:"proxyPort"`
	ListeningIp        string                           `yaml:"listening-ip,omitempty"`
	AuthKey            string                           `yaml:"auth-key"`
	SignKey            string                           `yaml:"sign-key"`
	MaxWorkers         int                              `yaml:"max-workers"`
	FileTransferRoot   string                           `yaml:"file-transfer-root"`
	OvaDir             string                           `yaml:"ova-dir"`
	StatePath          string                           `yaml:"state-path"`
	VPNService         VPNconf                          `yaml:"vpn-service"`
	DockerRepositories []dockerclient.AuthConfiguration `yaml:"docker-repositories"`
}

type VPNconf struct {
	Endpoint   string `yaml:"endpoint"`
	Port       uint64 `yaml:"port"`
	AuthKey    string `yaml:"auth-key"`
	SignKey    string `yaml:"sign-key"`
	WgConfDir  string `yaml:"wg-conf-dir"`
	TLSEnabled bool   `yaml:"tls-enabled"`
}

type ServiceConfig struct {
	Grpc       string `yaml:"grpc"`
	AuthKey    string `yaml:"auth-key"`
	SignKey    string `yaml:"sign-key"`
	TLSEnabled bool   `yaml:"tls-enabled"`
}

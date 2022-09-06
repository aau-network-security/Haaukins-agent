package agent

import (
	dockerclient "github.com/fsouza/go-dockerclient"
)

type Config struct {
	Host               string                           `yaml:"host"`
	Port               uint                             `yaml:"port"`
	AuthKey            string                           `yaml:"auth-key"`
	SignKey            string                           `yaml:"sign-key"`
	RedisDataPath      string                           `yaml:"redis-data-path"`
	FileTransferRoot   string                           `yaml:"file-transfer-root"`
	OvaDir             string                           `yaml:"ova-dir"`
	ExerciseService    ServiceConfig                    `yaml:"exercise-service"`
	VPNService         VPNconf                          `yaml:"vpn-service"`
	DockerRepositories []dockerclient.AuthConfiguration `yaml:"docker-repositories"`
	GuacSSL            bool                             `yaml:"guac-ssl"`
}

type VPNconf struct {
	Endpoint   string `yaml:"endpoint"`
	Port       string `yaml:"port"`
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

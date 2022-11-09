package agent

import (
	dockerclient "github.com/fsouza/go-dockerclient"
)

type Config struct {
	Host               string                           `yaml:"host"`
	GrpcPort           uint                             `yaml:"grpcPort"`
	ProxyPort          uint                             `yaml:"proxyPort"`
	AuthKey            string                           `yaml:"auth-key"`
	SignKey            string                           `yaml:"sign-key"`
	MaxWorkers         int                              `yaml:"max-workers"`
	RedisDataPath      string                           `yaml:"redis-data-path"`
	FileTransferRoot   string                           `yaml:"file-transfer-root"`
	OvaDir             string                           `yaml:"ova-dir"`
	ExerciseService    ServiceConfig                    `yaml:"exercise-service"`
	VPNService         VPNconf                          `yaml:"vpn-service"`
	DockerRepositories []dockerclient.AuthConfiguration `yaml:"docker-repositories"`
	GuacSSL            bool                             `yaml:"guac-ssl"`
	JwtSecret          string                           `yaml:"jwtSecret"`
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

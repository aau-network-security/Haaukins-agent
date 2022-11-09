package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/aau-network-security/haaukins-agent/internal/agent"
	pb "github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
)

const (
	defaultConfigFile = "config/config.yml"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	confFilePtr := flag.String("config", defaultConfigFile, "configuration file")
	flag.Parse()

	c, err := agent.NewConfigFromFile(*confFilePtr)
	if err != nil {
		log.Fatal().Err(err).Msgf("unable to read configuration file: %s", *confFilePtr)
		return
	}

	a, err := agent.New(c)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to create daemon")
		return
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", c.GrpcPort))
	if err != nil {
		log.Fatal().Msgf("failed to listen: %v", err)
	}

	opts := []grpc.ServerOption{}

	// go func() {
	// 	a.RunGuacProxy()
	// }()

	gRPCServer := a.NewGRPCServer(opts...)
	pb.RegisterAgentServer(gRPCServer, a)
	log.Info().Msg("server is waiting for clients")
	if err := gRPCServer.Serve(lis); err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}

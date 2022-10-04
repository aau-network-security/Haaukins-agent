package agent

import (
	"github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/rs/zerolog/log"
)

// For the daemon to listen to. New labs created with the workers are pushed to the daemon through the stream when they are created and running.
func (a *Agent) LabStream(req *proto.Empty, stream proto.Agent_LabStreamServer) error {
	for {
		select {
		case lab := <-a.newLabs:
			log.Debug().Msg("Lab in new lab channel, sending to client...")
			stream.Send(&lab)
		}
	}
}

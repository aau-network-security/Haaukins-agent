package agent

import (
	"context"
	"errors"
	"sync"

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

// TODO: Rethink func name as this should be the function that configures a lab for a user
// TODO: Handle assignment (Guac connection and VPN configs here)
func (a *Agent) CreateLabForEnv(ctx context.Context, req *proto.CreateLabRequest) (*proto.StatusResponse, error) {
	a.State.EnvPool.Em.RLock()
	env, ok := a.State.EnvPool.Envs[req.EventTag]
	a.State.EnvPool.Em.RUnlock()
	if !ok {
		return &proto.StatusResponse{}, errors.New("environment for event does not exist")
	}
	ec := env.EnvConfig

	m := &sync.RWMutex{}
	ec.WorkerPool.AddTask(func() {
		ctx := context.Background()

		// Creating containers etc.
		lab, err := ec.LabConf.NewLab(ctx, req.IsVPN, ec.Type, ec.Tag)
		if err != nil {
			log.Error().Err(err).Msg("error creating new lab")
			return
		}
		// Starting the created containers and frontends
		if err := lab.Start(ctx); err != nil {
			log.Error().Err(err).Msg("error starting new lab")
			return
		}
		// Sending lab info to daemon
		newLab := proto.Lab{
			Tag:      lab.Tag,
			EventTag: ec.Tag,
			IsVPN:    req.IsVPN,
		}

		a.newLabs <- newLab
		m.Lock()
		env.Labs[lab.Tag] = &lab
		m.Unlock()
	})
	return &proto.StatusResponse{Message: "OK"}, nil
}

package environment

import (
	"context"
	"sync"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
	"github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/rs/zerolog/log"
)

// TODO: Restructure folder structure, to be hierarchical
func (ec *EnvConfig) NewEnv(ctx context.Context, newLabs chan proto.Lab, labAmount int32) (*Environment, error) {
	// Make worker work

	var env *Environment
	
	// TODO Start labs as well in new lab before continueing
	guac, err := NewGuac(ctx, ec.Tag)
	if err != nil {
		return nil, err
	}
	log.Debug().Msgf("lab returned by NewLab: %v", lab)
	


	env.Labs = make(map[string]lab.Lab)
	m := &sync.RWMutex{}
	// If it is a beginner event, labs will be created and be available beforehand
	if labAmount > 0 {
		for i := 0; i < int(labAmount); i++ {
			// Adding lab creation task to taskqueue
			ec.WorkerPool.AddTask(func() {
				ctx := context.Background()
				// Creating containers and frontends
				lab, err := ec.LabConf.NewLab(ctx, false, ec.Tag)
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
				// TODO Figure out what exact data should be sent
				newLab := proto.Lab{
					Tag:      lab.Tag,
					EventTag: ec.Tag,
					IsVPN:    false,
				}
				newLabs <- newLab
				// Adding lab to environment
				m.Lock()
				env.Labs[lab.Tag] = lab
				m.Unlock()
			})
		}
	}

	
	return nil, nil
}

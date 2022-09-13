package environment

import (
	"context"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
	"github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/rs/zerolog/log"
)

// TODO: Restructure folder structure, to be hierarchical
func (ec *EnvConfig) NewEnv(ctx context.Context, newLabs chan proto.Lab, labAmount int32) (*Environment, error) {
	// Make worker work
	labs := map[string]lab.Lab{}

	// TODO put into worker
	lab, err := ec.LabConf.NewLab(ctx, false, ec.Tag, &labs)
	if err != nil {
		return nil, err
	}

	guac, err := NewGuac(ctx, "",  )
	log.Debug().Msgf("lab returned by NewLab: %v", lab)
	return nil, nil
}

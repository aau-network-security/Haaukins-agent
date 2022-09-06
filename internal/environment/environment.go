package environment

import "github.com/aau-network-security/haaukins-agent/pkg/proto"

// TODO: Restructure folder structure, to be hierarchical
func (ec *EnvConfig) NewEnv(newLabs chan proto.Lab, labAmount int, workerAmount int) (*Environment, error) {

	return nil, nil
}

func worker(ready chan struct{}) {
 
}

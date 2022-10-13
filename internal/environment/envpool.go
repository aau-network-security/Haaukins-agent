package environment

import (
	"errors"
	"fmt"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
)

// Returns a lab from the env pool if the lab tag exists in any of the environments
func (ep *EnvPool) GetLabByTag(tag string) (*lab.Lab, error) {
	for ke, e := range ep.Envs {
		for kl, l := range e.Labs {
			if l.Tag == tag {
				// To make sure that lab is by reference and not by value
				return ep.Envs[ke].Labs[kl], nil
			}
		}
	}
	return nil, errors.New(fmt.Sprintf("could not find lab with tag: %s", tag))
}

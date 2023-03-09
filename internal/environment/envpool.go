package environment

import (
	"fmt"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
)

func (ep *EnvPool) AddEnv(env *Environment) {
	ep.M.Lock()
	defer ep.M.Unlock()

	ep.Envs[env.EnvConfig.Tag] = env
}

func (ep *EnvPool) GetEnv(tag string) (*Environment, error) {
	ep.M.RLock()
	defer ep.M.RUnlock()

	if _, ok := ep.Envs[tag]; !ok {
		return nil, fmt.Errorf("could not find environment with tag: %s ", tag)
	}

	return ep.Envs[tag], nil
}

func (ep *EnvPool) DoesEnvExist(tag string) bool {
	ep.M.RLock()
	defer ep.M.RUnlock()

	_, ok := ep.Envs[tag]

	return ok
}

// Returns a lab from the env pool if the lab tag exists in any of the environments
func (ep *EnvPool) GetLabByTag(tag string) (*lab.Lab, error) {
	ep.M.Lock()
	defer ep.M.Unlock()

	for ke, e := range ep.Envs {
		e.M.Lock()
		
		for kl, l := range e.Labs {
			if l.Tag == tag {
				// To make sure that lab is by reference and not by value
				e.M.Unlock()
				return ep.Envs[ke].Labs[kl], nil
			}
		}
		e.M.Unlock()
	}
	return nil, fmt.Errorf("could not find lab with tag: %s", tag)
}

func (ep *EnvPool) GetFullLabCount() (uint32) {
	ep.M.RLock()
	defer ep.M.RUnlock()
	var count uint32
	for _, env := range ep.Envs {
		for range env.Labs {
			count++
		}
	}
	return count
}

// Removes an environment from the environment pool
func (ep *EnvPool) RemoveEnv(tag string) error {
	ep.M.Lock()
	defer ep.M.Unlock()

	if _, ok := ep.Envs[tag]; !ok {
		return fmt.Errorf("could not find environment with tag: %s ", tag)
	}

	delete(ep.Envs, tag)
	return nil
}

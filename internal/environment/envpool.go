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
			l.M.Lock()
			if l.Tag == tag {
				// To make sure that lab is by reference and not by value
				l.M.Unlock()
				e.M.Unlock()
				return ep.Envs[ke].Labs[kl], nil
			}
			l.M.Unlock()
		}
		e.M.Unlock()
	}
	return nil, fmt.Errorf("could not find lab with tag: %s", tag)
}

func (ep *EnvPool) GetFullLabCount() uint32 {
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

func (ep *EnvPool) LockForFunc(function func()) {
	ep.M.Lock()
	defer ep.M.Unlock()

	function()
}

func (ep *EnvPool) GetEnvList() (envList map[string]bool) {
	ep.M.RLock()
	defer ep.M.RUnlock()
	envList = make(map[string]bool)
	for eventTag := range ep.Envs {
		envList[eventTag] = true
	}
	return
}

func (ep *EnvPool) GetStartingEnvs() map[string]bool {
	ep.M.RLock()
	defer ep.M.RUnlock()

	return ep.StartingEnvs
}

func (ep *EnvPool) AddStartingEnv(eventTag string) {
	ep.M.Lock()
	defer ep.M.Unlock()

	ep.StartingEnvs[eventTag] = true
}

func (ep *EnvPool) RemoveStartingEnv(eventTag string) {
	ep.M.Lock()
	defer ep.M.Unlock()

	delete(ep.StartingEnvs, eventTag)
}

func (ep *EnvPool) GetClosingEnvs() map[string]bool {
	ep.M.RLock()
	defer ep.M.RUnlock()

	return ep.ClosingEnvs
}

func (ep *EnvPool) AddClosingEnv(eventTag string) {
	ep.M.Lock()
	defer ep.M.Unlock()

	ep.ClosingEnvs[eventTag] = true
}

func (ep *EnvPool) RemoveClosingEnv(eventTag string) {
	ep.M.Lock()
	defer ep.M.Unlock()

	delete(ep.ClosingEnvs, eventTag)
}

package lab

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/exercise"
	"github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/hashicorp/go-multierror"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/slices"
)

// AddExercises uses exercise configs from the exercise service to configure containers and flags to be started at a later time
func (l *Lab) AddExercises(ctx context.Context, confs ...exercise.ExerciseConfig) error {
	var e *exercise.Exercise
	var aRecord string

	for _, conf := range confs {
		if conf.Tag == "" {
			return errors.New("No tags, need atleast one tag")
		}

		if _, ok := l.Exercises[conf.Tag]; ok {
			return errors.New("Tag already exists")
		}

		if conf.Static {
			// TODO remove static exercises on agent side, but need the overview first
			e = exercise.NewExercise(conf, nil, nil, "")
		} else {
			e = exercise.NewExercise(conf, l.Vlib, l.Network, l.DnsAddress)
			if err := e.Create(ctx); err != nil {
				return err
			}
			ip := strings.Split(e.DnsAddr, ".")

			for i, c := range e.ContainerOpts {
				for _, r := range c.Records {
					if strings.Contains(c.DockerConf.Image, "client") {
						continue
					}
					if r.Type == "A" {
						aRecord = r.Name
						l.DnsRecords = append(l.DnsRecords, &DNSRecord{Record: map[string]string{
							fmt.Sprintf("%s.%s.%s.%d", ip[0], ip[1], ip[2], e.Ips[i]): aRecord,
						}})
					}
				}
			}
		}
		l.Exercises[conf.Tag] = e
		//.Exercises = append(l.Exercises, e)
	}

	return nil
}

// Used to add exercises to an already running lab.
// It configures the containers, refreshes the DNS to add the new records and then starts the new exercise containers
func (l *Lab) AddAndStartExercises(ctx context.Context, exerConfs ...exercise.ExerciseConfig) error {
	l.M.Lock()
	defer l.M.Unlock()

	if err := l.AddExercises(ctx, exerConfs...); err != nil {
		log.Error().Err(err).Msg("error adding exercise to lab")
		return err
	}

	// Refresh the DNS
	if err := l.RefreshDNS(ctx); err != nil {
		log.Error().Err(err).Msg("error refreshing DNS")
		return err
	}

	newExTags := []string{}
	for _, exerConf := range exerConfs {
		newExTags = append(newExTags, exerConf.Tag)
	}

	// Start the exercises
	var res error
	var wg sync.WaitGroup
	for _, ex := range l.Exercises {
		if slices.Contains(newExTags, ex.Tag) {
			wg.Add(1)
			go func(e *exercise.Exercise) {
				if err := e.Start(ctx); err != nil {
					res = multierror.Append(res, err)
				}
				wg.Done()
			}(ex)
		}

	}
	wg.Wait()
	if res != nil {
		return res
	}
	return nil
}

// TODO: Set status of exercise so user can see weither if it is started or stopped.
func (l *Lab) StartExercise(ctx context.Context, exTag string) error {
	e, ok := l.Exercises[exTag]
	if !ok {
		return fmt.Errorf("could not find exercise with tag: %s", exTag)
	}

	if err := e.Start(ctx); err != nil {
		return err
	}
	return nil
}

func (l *Lab) StopExercise(ctx context.Context, exTag string) error {
	e, ok := l.Exercises[exTag]
	if !ok {
		return fmt.Errorf("could not find exercise with tag: %s", exTag)
	}

	if err := e.Stop(ctx); err != nil {
		return err
	}
	return nil
}

func (l *Lab) ResetExercise(ctx context.Context, exTag string) error {
	e, ok := l.Exercises[exTag]
	if !ok {
		return fmt.Errorf("could not find exercise with tag: %s", exTag)
	}

	if err := e.Reset(ctx); err != nil {
		return err
	}
	return nil
}

// Returns all exercises currently in lab to be sent to the daemon
func (l *Lab) GetExercisesInfo() []*proto.Exercise {
	var exercises []*proto.Exercise
	for _, e := range l.Exercises {
		var machines []*proto.Machine
		for _, m := range e.Machines {
			machine := &proto.Machine{
				Id:     m.Info().Id,
				Status: m.Info().State.String(),
				Type:   m.Info().Type,
				Image:  m.Info().Image,
			}
			machines = append(machines, machine)
		}

		childExercises := e.GetChildExercises()
		var protoChildExercises []*proto.ChildExercise
		for _, childExercise := range childExercises {
			protoChildExercise := &proto.ChildExercise{
				Tag:  childExercise.Tag,
				Flag: childExercise.Value,
			}
			protoChildExercises = append(protoChildExercises, protoChildExercise)
		}

		exercise := &proto.Exercise{
			Tag:            e.Tag,
			ChildExercises: protoChildExercises,
			Machines:       machines,
		}
		exercises = append(exercises, exercise)
	}
	return exercises
}

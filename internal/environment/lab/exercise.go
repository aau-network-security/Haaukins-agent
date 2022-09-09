package lab

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/exercise"
)

func (l *Lab) AddExercises(ctx context.Context, confs ...exercise.ExerciseConfig) error {
	var e *exercise.Exercise
	var aRecord string

	for _, conf := range confs {
		if conf.Tag == "" {
			return errors.New("No tags, need atleast one tag")
		}

		if _, ok := l.ExTags[conf.Tag]; ok {
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
		l.ExTags[conf.Tag] = e
		l.Exercises = append(l.Exercises, e)
	}

	return nil
}

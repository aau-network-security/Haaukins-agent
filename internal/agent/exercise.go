package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/exercise"
	"github.com/aau-network-security/haaukins-agent/pkg/proto"
	eproto "github.com/aau-network-security/haaukins-exercises/proto"
	"github.com/rs/zerolog/log"
)

// GRPc endpoint that adds exercises to an already running lab. It requires the lab tag, and an array of exercise tags.
// It starts by creating the containers needed for the exercise, then it refreshes the DNS and starts the containers afterwards.
// It utilizes a mutex lock to make sure that if anyone tries to run the same GRPc call twice without the first being finished, the second one will wait
func (a *Agent) AddExercisesToLab(ctx context.Context, req *proto.AddExerciseRequest) (*proto.StatusResponse, error) {

	lab, err := a.State.EnvPool.GetLabByTag(req.LabTag)
	lab.M.Lock()
	defer lab.M.Unlock()

	if err != nil {
		log.Error().Str("labTag", req.LabTag).Err(err).Msg("error getting lab by tag")
		return nil, err
	}

	var exerConfs []exercise.ExerciseConfig
	exerDbConfs, err := a.State.ExClient.GetExerciseByTags(ctx, &eproto.GetExerciseByTagsRequest{Tag: req.Exercises})
	if err != nil {
		log.Error().Err(err).Msg("error getting exercise by tags")
		return nil, errors.New(fmt.Sprintf("error getting exercises: %s", err))
	}
	//log.Debug().Msgf("challenges: %v", exerDbConfs)
	// Unpack into exercise slice
	for _, e := range exerDbConfs.Exercises {
		ex, err := protobufToJson(e)
		if err != nil {
			return nil, err
		}
		estruct := exercise.ExerciseConfig{}
		json.Unmarshal([]byte(ex), &estruct)
		exerConfs = append(exerConfs, estruct)
	}

	// Add exercises to lab
	ctx = context.Background()
	if err := lab.AddExercises(ctx, exerConfs...); err != nil {
		log.Error().Err(err).Msg("error adding exercise to lab")
		return nil, err
	}

	// Refresh the DNS
	if err := lab.RefreshDNS(ctx); err != nil {
		log.Error().Err(err).Msg("error refreshing DNS")
		return nil, err
	}
	oldLab, _ := a.State.EnvPool.GetLabByTag(req.LabTag)
	log.Debug().Str("oldLab", oldLab.DnsServer.Container().ID()).Str("newLab", lab.DnsServer.Container().ID()).Msg("old vs new lab")

	// Start the exercises
	var res error
	var wg sync.WaitGroup
	for _, ex := range lab.Exercises {
		wg.Add(1)
		go func(e *exercise.Exercise) {
			if err := e.Start(ctx); err != nil {
				res = err
			}
			wg.Done()
		}(ex)
	}
	wg.Wait()
	if res != nil {
		return nil, res
	}

	// TODO: Need to return host information back to daemon to display to user in case of VPN lab
	return &proto.StatusResponse{Message: "OK"}, nil
}

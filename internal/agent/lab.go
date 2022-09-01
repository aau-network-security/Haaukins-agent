package agent

import (
	"context"
	"encoding/json"

	"github.com/aau-network-security/haaukins-agent/internal/lab"
	"github.com/aau-network-security/haaukins-agent/internal/virtual/vbox"
	"github.com/aau-network-security/haaukins-agent/pkg/proto"
	eproto "github.com/aau-network-security/haaukins-exercises/proto"
	"github.com/rs/zerolog/log"
)

func (a *Agent) CreateLabs(ctx context.Context, req *proto.CreateLabsRequest) (*proto.CreateLabsResponse, error) {
	// Env for event already exists, Do not start a new guac container
	if _, ok := a.State.EnvPool.Envs[req.EventTag]; ok {

		return &proto.CreateLabsResponse{Message: "Recieved labs"}, nil
	}

	// Create a new lab environment for event if it does not exists
	// Setting up the lab config
	var labConf lab.Config
	var exers []lab.Exercise
	exer, err := a.State.exClient.GetExerciseByTags(ctx, &eproto.GetExerciseByTagsRequest{Tag: req.Exercises})
	if err != nil {
		return nil, err
	}
	for _, e := range exer.Exercises {
		exercise, err := protobufToJson(e)
		if err != nil {
			return nil, err
		}
		estruct := lab.Exercise{}
		json.Unmarshal([]byte(exercise), &estruct)
		exers = append(exers, estruct)
	}
	labConf.Exercises = exers
	var frontends = []vbox.InstanceConfig{}
	for _, f := range req.Vms.VmConfigs {
		frontend := vbox.InstanceConfig{
			Image:    f.Image,
			MemoryMB: uint(f.MemoryMB),
			CPU:      f.Cpu,
		}
		frontends = append(frontends, frontend)
	}
	labConf.Frontends = append(labConf.Frontends, frontends...)

	lh := lab.LabHost{
		Vlib: a.vlib,
		Conf: labConf,
	}
	return &proto.CreateLabsResponse{Message: "Recieved labs"}, nil
}

func (a *Agent) LabStream(req *proto.Empty, stream proto.Agent_LabStreamServer) error {
	for {
		select {
		case lab := <-a.newLabs:
			log.Debug().Msg("Lab in new lab channel, sending to client...")
			stream.Send(&lab)
		}
	}
}

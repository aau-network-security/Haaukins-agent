package agent

import (
	"context"

	"github.com/aau-network-security/haaukins-agent/pkg/proto"
)

// TODO Heartbeat, resource monitoring and log monitoring

func (a *Agent) Ping(ctx context.Context, req *proto.PingRequest) (*proto.PingResponse, error) {
	if req.Ping == "ping" {
		return &proto.PingResponse{Pong: "pong"}, nil
	}
	return &proto.PingResponse{Pong: "the hell is that kind of ping?"}, nil
}

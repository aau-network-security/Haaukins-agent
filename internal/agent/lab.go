package agent

import (
	"context"
	"fmt"

	"github.com/aau-network-security/haaukins-agent/internal/proto"
)

func (d *Agent) CreateLabs(ctx context.Context, req *proto.TestCallRequest) (*proto.TestCallResponse, error) {
	return &proto.TestCallResponse{Message: fmt.Sprintf("Recieved message: %s", req.Message)}, nil
}

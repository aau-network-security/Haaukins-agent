package agent

import (
	"context"
	"io"

	"github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
)

// TODO Heartbeat, resource monitoring and log monitoring
// Used for the daemon to check the connection to the agent when initially connecting
func (a *Agent) Ping(ctx context.Context, req *proto.PingRequest) (*proto.PingResponse, error) {
	if req.Ping == "ping" {
		return &proto.PingResponse{Pong: "pong"}, nil
	}
	return &proto.PingResponse{Pong: "the hell is that kind of ping?"}, nil
}

// Monitoring stream will respond to Pings from the server with cpu, memory and any new labs that may have come since last request
func (a *Agent) MonitorStream(stream proto.Agent_MonitorStreamServer) error {
	log.Debug().Msg("client connected to monitoring stream")
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			log.Debug().Msg("client closing connection")
			return nil
		}
		if err != nil {
			log.Error().Err(err).Msg("error recieving monitoring ping from client")
			if err.Error() == "rpc error: code = Canceled desc = context canceled" {
				return nil
			}
			continue
		}
		cpuPerc, err := cpu.Percent(0, false)
		if err != nil {
			log.Error().Err(err).Msg("error reading cpu percentage")
			cpuPerc = append(cpuPerc, 0)
		}
		memory, err := mem.VirtualMemory()
		if err != nil {
			log.Error().Err(err).Msg("error reading memory percentage")
			memory = &mem.VirtualMemoryStat{}
			memory.UsedPercent = 0
		}

		resp := &proto.MonitorResponse{
			Hb:  "alive",
			Cpu: cpuPerc[0],
			Mem: memory.UsedPercent,
		}
		for i, l := range a.newLabs {
			resp.NewLabs = append(resp.NewLabs, &l)
			a.newLabs = popFromNewLabSlice(a.newLabs, i)
		}

		if err := stream.Send(resp); err != nil {
			log.Error().Err(err).Msg("error sending monitoring response")
		}
	}
}

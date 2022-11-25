package agent

import (
	"github.com/gogo/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	aproto "github.com/aau-network-security/haaukins-agent/pkg/proto"
)

func protobufToJson(message proto.Message) (string, error) {
	marshaler := jsonpb.Marshaler{
		EnumsAsInts:  false,
		EmitDefaults: false,
		Indent:       "  ",
	}

	return marshaler.MarshalToString(message)
}

func popFromNewLabSlice(labs []aproto.Lab, i int) []aproto.Lab {
    labs[i] = labs[len(labs)-1]
    return labs[:len(labs)-1]
}
package agent

import (
	"github.com/gogo/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
)

func protobufToJson(message proto.Message) (string, error) {
	marshaler := jsonpb.Marshaler{
		EnumsAsInts:  false,
		EmitDefaults: false,
		Indent:       "  ",
	}

	return marshaler.MarshalToString(message)
}

// Copyright (c) 2018-2019 Aalborg University
// Use of this source code is governed by a GPLv3
// license that can be found in the LICENSE file.

package dns

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"

	"io"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
	"github.com/rs/zerolog/log"
)

const (
	PreferedIP      = 3
	coreFileContent = `. {
    file zonefile
    prometheus     # enable metrics
    errors         # show errors
    log            # enable query logs
}
`
	zonePrefixContent = `$ORIGIN .
@   3600 IN SOA sns.dns.icann.org. noc.dns.icann.org. (
                2017042745 ; serial
                7200       ; refresh (2 hours)
                3600       ; retry (1 hour)
                1209600    ; expire (2 weeks)
                3600       ; minimum (1 hour)
                )

`
)

type Server struct {
	Cont      *virtual.Container
	ConfFile  string
	io.Closer `json:"-"`
}

type RR struct {
	Name  string
	Type  string
	RData string
}

// TODO add comments
func (rr *RR) Format() string {
	return fmt.Sprintf("%s IN %s %s", rr.Name, rr.Type, rr.RData)
}

func New(records []RR) (*Server, error) {
	f, err := ioutil.TempFile("", "zonefile")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	c, err := ioutil.TempFile("", "Corefile")
	if err != nil {
		return nil, err
	}
	defer c.Close()

	confFile := f.Name()

	f.Write([]byte(zonePrefixContent))

	for _, r := range records {
		_, err = f.Write([]byte(r.Format() + "\n"))
		if err != nil {
			return nil, err
		}
	}

	coreFile := c.Name()

	c.Write([]byte(coreFileContent))

	f.Sync()
	cont := virtual.NewContainer(virtual.ContainerConfig{
		Image: "coredns/coredns:1.6.1",
		Mounts: []string{
			fmt.Sprintf("%s:/Corefile", coreFile),
			fmt.Sprintf("%s:/zonefile", confFile),
		},
		UsedPorts: []string{
			"53/tcp",
			"53/udp",
		},
		Resources: &virtual.Resources{
			MemoryMB: 50,
			CPU:      0.3,
		},
		Cmd: []string{"--conf", "Corefile"},
		Labels: map[string]string{
			"hkn": "lab_dns",
		},
	})

	return &Server{
		Cont:     cont,
		ConfFile: confFile,
	}, nil
}

func (s *Server) Container() *virtual.Container {
	return s.Cont
}

func (s *Server) Run(ctx context.Context) error {
	return s.Cont.Run(ctx)
}

func (s *Server) Close() error {
	if err := os.Remove(s.ConfFile); err != nil {
		log.Warn().Msgf("error while removing DNS configuration file: %s", err)
	}

	if err := s.Cont.Close(); err != nil {
		log.Warn().Msgf("error while closing DNS container: %s", err)
	}

	return nil
}

func (s *Server) Stop() error {
	return s.Cont.Stop()
}

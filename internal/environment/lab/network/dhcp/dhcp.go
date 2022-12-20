// Copyright (c) 2018-2019 Aalborg University
// Use of this source code is governed by a GPLv3
// license that can be found in the LICENSE file.

package dhcp

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/dns"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
)

type Server struct {
	Cont     *virtual.Container
	ConfFile string
	Dns      string
	Subnet   string
}

// TODO add comments
func New(format func(n int) string) (*Server, error) {
	f, err := ioutil.TempFile("", "dhcpd-conf")
	if err != nil {
		return nil, err
	}
	confFile := f.Name()

	subnet := format(0)
	dns := format(dns.PreferedIP)
	// TODO: Test how resetting could affect docker IPs
	minRange := format(4)
	maxRange := format(254)
	broadcast := format(255)
	router := format(1)

	confStr := fmt.Sprintf(
		`option domain-name-servers %s;

	subnet %s netmask 255.255.255.0 {
		range %s %s;
		option subnet-mask 255.255.255.0;
		option broadcast-address %s;
		option routers %s;
	}`, dns, subnet, minRange, maxRange, broadcast, router)

	_, err = f.WriteString(confStr)
	if err != nil {
		return nil, err
	}
	cont := virtual.NewContainer(virtual.ContainerConfig{
		Image: "networkboot/dhcpd:1.2.0",
		Mounts: []string{
			fmt.Sprintf("%s:/data/dhcpd.conf", confFile),
		},
		DNS:       []string{dns},
		UsedPorts: []string{"67/udp"},
		Resources: &virtual.Resources{
			MemoryMB: 50,
			CPU:      0.3,
		},
		Cmd: []string{"eth0"},
		Labels: map[string]string{
			"hkn": "lab_dhcpd",
		},
	})

	return &Server{
		Cont:     cont,
		ConfFile: confFile,
		Dns:      dns,
		Subnet:   subnet,
	}, nil
}

func (dhcp *Server) Container() *virtual.Container {
	return dhcp.Cont
}

func (dhcp *Server) Run(ctx context.Context) error {
	return dhcp.Cont.Run(ctx)
}

func (dhcp *Server) Close() error {
	if err := os.Remove(dhcp.ConfFile); err != nil {
		return err
	}

	if err := dhcp.Cont.Close(); err != nil {
		return err
	}

	return nil
}
func (dhcp *Server) LabSubnet() string {
	return dhcp.Subnet
}

func (dhcp *Server) LabDNS() string {
	return dhcp.Dns
}

func (dhcp *Server) Stop() error {
	return dhcp.Cont.Stop()
}

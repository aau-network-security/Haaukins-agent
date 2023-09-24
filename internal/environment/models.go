package environment

import (
	"net/http"
	"sync"

	wgproto "github.com/aau-network-security/gwireguard/proto" //v1.0.3
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
	wg "github.com/aau-network-security/haaukins-agent/internal/environment/lab/network/vpn"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
	"github.com/aau-network-security/haaukins-agent/internal/worker"
)

// General environment types
type EnvPool struct {
	M *sync.RWMutex
	// Map of environments with eventTag as key
	Envs         map[string]*Environment
	StartingEnvs map[string]bool
	ClosingEnvs  map[string]bool
}

type Environment struct {
	M             *sync.RWMutex
	EnvConfig     *EnvConfig
	Guac          Guacamole
	IpT           IPTables
	IpRules       map[string]IpRules
	IpAddrs       [][]int
	Wg            wgproto.WireguardClient
	GuacUserStore *GuacUserStore
	Dockerhost    virtual.Host
	Labs          map[string]*lab.Lab
	// Fill out rest when starting to make labs
}

type Status uint8

const (
	StatusRunning Status = iota
	StatusUpdating
	StatusClosing
	StatusClosed
)

type EnvConfig struct {
	Tag             string
	TeamSize        int
	Type            lab.LabType
	VPNAddress      string
	VPNEndpointPort int
	VpnConfig       wg.WireGuardConfig
	WorkerPool      worker.WorkerPool
	LabConf         lab.LabConf
	Status          Status
}

type Category struct {
	Tag            string `json:"tag,omitempty"`
	Name           string `json:"name,omitempty"`
	CatDescription string `json:"catDesc,omitempty"`
}

type Profile struct {
	Name       string       `json:"name,omitempty"`
	Secret     bool         `json:"secret,omitempty"`
	Challenges []PChallenge `json:"challenges,omitempty"`
}

type PChallenge struct {
	Tag  string `json:"tag,omitempty"`
	Name string `json:"name,omitempty"`
}

type IpRules struct {
	Labsubnet string
	VpnIps    string
}

// Guac types
type Guacamole struct {
	Client     *http.Client
	Token      string
	Port       uint
	AdminPass  string
	Containers map[string]*virtual.Container
}

type createUserAttributes struct {
	Disabled          string  `json:"disabled"`
	Expired           string  `json:"expired"`
	AccessWindowStart string  `json:"access-window-start"`
	AccessWindowEnd   string  `json:"access-window-end"`
	ValidFrom         string  `json:"valid-from"`
	ValidUntil        string  `json:"valid-until"`
	TimeZone          *string `json:"timezone"`
}

type createUserInput struct {
	Username   string               `json:"username"`
	Password   string               `json:"password"`
	Attributes createUserAttributes `json:"attributes"`
}

type GuacUser struct {
	Username string
	Password string
}

type GuacUserStore struct {
	m     sync.RWMutex
	teams map[string]GuacUser
}

type createRDPConnAttr struct {
	FailOverOnly     *bool   `json:"failover-only"`
	GuacdEncripytion *string `json:"guacd-encryption"`
	GuacdPort        *uint   `json:"guacd-port"`
	MaxConn          uint    `json:"max-connections"`
	MaxConnPerUser   uint    `json:"max-connections-per-user"`
	Weight           *uint   `json:"weight"`
}

type createRDPConnConf struct {
	ClipboardEncoding        *string `json:"clipboard-encoding"`
	ColorDepth               *uint   `json:"color-depth"`
	Console                  *string `json:"console"`
	ConsoleAudio             *string `json:"console-audio"`
	Cursor                   *string `json:"cursor"`
	DestPort                 *uint   `json:"dest-port"`
	DisableAudio             *bool   `json:"disable-audio"`
	DisableAuth              *bool   `json:"disable-auth"`
	DPI                      *uint   `json:"dpi"`
	EnableAudio              *bool   `json:"enable-audio"`
	EnableAudioInput         *bool   `json:"enable-audio-input"`
	EnableDesktopComposition *bool   `json:"enable-desktop-composition"`
	EnableDrive              *bool   `json:"enable-drive"`
	EnableFontSmoothing      *bool   `json:"enable-font-smoothing"`
	EnableFullWindowDrag     *bool   `json:"enable-full-window-drag"`
	EnableMenuAnimations     *bool   `json:"enable-menu-animations"`
	EnablePrinting           *bool   `json:"enable-printing"`
	EnableSFTP               *bool   `json:"enable-sftp"`
	EnableTheming            *bool   `json:"enable-theming"`
	EnableWallpaper          *bool   `json:"enable-wallpaper"`
	GatewayPort              *uint   `json:"gateway-port"`
	Height                   *uint   `json:"height"`
	Width                    *uint   `json:"width"`
	Hostname                 *string `json:"hostname"`
	IgnoreCert               *bool   `json:"ignore-cert"`
	Port                     *uint   `json:"port"`
	PreConnectionID          *uint   `json:"preconnection-id"`
	ReadOnly                 *bool   `json:"read-only"`
	ResizeMethod             *string `json:"resize-method"`
	Security                 *string `json:"security"`
	ServerLayout             *string `json:"server-layout"`
	SFTPPort                 *uint   `json:"sftp-port"`
	SFTPAliveInterval        *uint   `json:"sftp-server-alive-interval"`
	SwapRedBlue              *bool   `json:"swap-red-blue"`
	CreateDrivePath          *bool   `json:"create-drive-path"`
	DrivePath                *string `json:"drive-path"`
	Username                 *string `json:"username,omitempty"`
	Password                 *string `json:"password,omitempty"`
}

type CreateRDPConnOpts struct {
	Host             string
	Port             uint
	Name             string
	GuacUser         string
	Username         *string
	Password         *string
	EnableWallPaper  *bool
	ResolutionWidth  uint
	ResolutionHeight uint
	MaxConn          uint
	ColorDepth       uint
	EnableDrive      *bool
	CreateDrivePath  *bool
	DrivePath        *string
}

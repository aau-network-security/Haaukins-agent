package environment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

var (
	DefaultAdminUser = "guacadmin"
	DefaultAdminPass = "guacadmin"
)

// TODO Go through all the code, make sure it makes sense, comment the code
type GuacError struct {
	action string
	err    error
}

func (ge *GuacError) Error() string {
	return fmt.Sprintf("guacamole: trying to %s. failed: %s", ge.action, ge.err)
}

// Creates a new Guacamole struct for an environment.
func NewGuac(ctx context.Context, eventTag string) (Guacamole, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return Guacamole{}, err
	}

	client := &http.Client{
		Jar: jar,
	}

	adminPass := uuid.New().String()
	log.Debug().Str("guacpassword", adminPass).Msg("setting password for guac")
	guac := Guacamole{
		Client:    client,
		AdminPass: adminPass,
	}

	if err := guac.create(ctx, eventTag); err != nil {
		log.Error().Err(err).Msg("error creating guac containers")
		return Guacamole{}, err
	}
	return guac, nil
}

/*
Creates the necessary containers for guacamole and configures the instance with a new admin password
*/
func (guac *Guacamole) create(ctx context.Context, eventTag string) error {
	if err := virtual.CreateEventFolder(eventTag); err != nil {
		log.Warn().Err(err).Msg("error creating event folder, filetransfer may not be available for this event on this agent")
	}

	// If user is not specified, filetransfer mount is owned by root, and can therefore not be accessed by vbox vm
	user := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	log.Debug().Str("user", user).Msg("starting guacd")

	containers := map[string]*virtual.Container{}

	containers["guacd"] = virtual.NewContainer(virtual.ContainerConfig{
		Image:     "guacamole/guacd:1.5.3",
		UseBridge: true,
		Labels: map[string]string{
			"hkn": "guacamole_guacd",
		},
		Mounts: []string{
			virtual.FileTransferRoot + "/" + eventTag + "/:/home/",
		},
		User: user,
	})

	mysqlPass := uuid.New().String()
	log.Debug().Str("mysqlPass", mysqlPass).Msg("mysql pw for guac")
	containers["db"] = virtual.NewContainer(virtual.ContainerConfig{
		Image: "ghcr.io/campfire-security/guac-db:latest",
		EnvVars: map[string]string{
			"MYSQL_ROOT_PASSWORD": uuid.New().String(),
			"MYSQL_DATABASE":      "guacamole_db",
			"MYSQL_USER":          "guacamole_user",
			"MYSQL_PASSWORD":      mysqlPass,
		},
		Labels: map[string]string{
			"hkn": "guacamole_db",
		},
	})

	guac.Port = virtual.GetAvailablePort()
	guacdAlias := uuid.New().String()
	dbAlias := uuid.New().String()
	containers["web"] = virtual.NewContainer(virtual.ContainerConfig{
		Image: "guacamole/guacamole:1.5.3",
		EnvVars: map[string]string{
			"MYSQL_DATABASE": "guacamole_db?useSSL=false",
			"MYSQL_USER":     "guacamole_user",
			"MYSQL_PASSWORD": mysqlPass,
			"GUACD_HOSTNAME": guacdAlias,
			"MYSQL_HOSTNAME": dbAlias,
		},
		PortBindings: map[string]string{
			"8080/tcp": fmt.Sprintf("127.0.0.1:%d", guac.Port),
		},
		UseBridge: true,
		Labels: map[string]string{
			"hkn": "guacamole_web",
		},
	})

	closeAll := func() {
		for _, c := range containers {
			c.Close()
		}
	}

	// Run the containers for configuration purposes
	for _, cname := range []string{"guacd", "db", "web"} {
		c := containers[cname]

		if err := c.Run(ctx); err != nil {
			closeAll()
			return err
		}

		var alias string
		switch cname {
		case "guacd":
			alias = guacdAlias
		case "db":
			alias = dbAlias
		}

		if _, err := c.BridgeAlias(alias); err != nil {
			closeAll()
			return err
		}
	}

	// Configure guacamole for the environment
	if err := guac.configureInstance(); err != nil {
		closeAll()
		return err
	}

	guac.Containers = containers

	return nil
}

func (guac *Guacamole) Close() error {
	for _, c := range guac.Containers {
		c.Close()
	}
	return nil
}

// Connects VMs in a lab to the corresponding guacamole instance for the environment.
func (env *Environment) CreateGuacConn(lab lab.Lab) error {
	enableWallPaper := true
	enableDrive := true
	createDrivePath := true
	// Drive path is the home folder inside the docker guacamole
	drivePath := "/home/" + lab.GuacUsername
	rdpPorts := lab.RdpConnPorts()
	if n := len(rdpPorts); n == 0 {
		log.
			Debug().
			Int("amount", n).
			Msg("Too few RDP connections")

		return errors.New("error too few rdp connections")
	}

	log.Debug().Str("username", lab.GuacUsername).Str("password", lab.GuacPassword).Msg("creating guac user with credentials")
	u := GuacUser{
		Username: lab.GuacUsername,
		Password: lab.GuacPassword,
	}

	if err := env.Guac.CreateUser(u.Username, u.Password); err != nil {
		log.
			Debug().
			Str("err", err.Error()).
			Msg("Unable to create guacamole user")
		return err
	}

	hostIp, err := env.Dockerhost.GetDockerHostIP()
	if err != nil {
		return err
	}

	for i, port := range rdpPorts {
		num := i + 1
		name := fmt.Sprintf("%s-client%d", lab.GuacUsername, num)

		log.Debug().Uint("port", port).Msg("Creating RDP Connection for lab")
		if err := env.Guac.CreateRDPConn(CreateRDPConnOpts{
			Host:            hostIp,
			Port:            port,
			Name:            name,
			GuacUser:        u.Username,
			Username:        &u.Username,
			Password:        &u.Password,
			EnableWallPaper: &enableWallPaper,
			EnableDrive:     &enableDrive,
			CreateDrivePath: &createDrivePath,
			DrivePath:       &drivePath,
		}); err != nil {
			return err
		}
	}

	instanceInfo := lab.InstanceInfo()
	// Will not handle error below since this is not a critical function
	_ = virtual.CreateUserFolder(lab.GuacUsername, env.EnvConfig.Tag)

	for i := 0; i < len(rdpPorts); i++ {
		if err := virtual.CreateFolderLink(instanceInfo[i].Id, env.EnvConfig.Tag, lab.GuacUsername); err != nil {
			log.Error().Err(err).Str("instanceId", instanceInfo[i].Id).Msg("error creating folder link for instance with id")
		}
	}

	return nil
}

// Creates a new user in Apache guacamole which can access a specific set of VMs
func (guac *Guacamole) CreateUser(username, password string) error {
	action := func(t string) (*http.Response, error) {
		data := createUserInput{
			Username: username,
			Password: password,
		}
		jsonData, _ := json.Marshal(data)
		endpoint := guac.baseUrl() + "/guacamole/api/session/data/mysql/users?token=" + t

		req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		return guac.Client.Do(req)
	}

	var output struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := guac.authAction("create user", action, &output); err != nil {
		return err
	}

	return nil
}

// Creates the Apache Guacamole RDP connection to a specific vm
func (guac *Guacamole) CreateRDPConn(opts CreateRDPConnOpts) error {
	if opts.Host == "" {
		return errors.New("host is missing")
	}

	if opts.Port == 0 {
		return errors.New("port is missing")
	}

	if opts.Name == "" {
		return errors.New("name is missing")
	}

	if opts.ResolutionWidth == 0 || opts.ResolutionHeight == 0 {
		opts.ResolutionWidth = 1920
		opts.ResolutionHeight = 1080
	}

	if opts.MaxConn == 0 {
		opts.MaxConn = 10
	}

	if opts.ColorDepth%8 != 0 || opts.ColorDepth > 32 {
		return errors.New("colorDepth can take the following values: 8, 16, 24, 32")
	}

	if opts.ColorDepth == 0 {
		opts.ColorDepth = 16
	}
	log.Debug().Str("drive-path", *opts.DrivePath).Msg("Drivepath for user is")
	conf := createRDPConnConf{
		Hostname:        &opts.Host,
		Width:           &opts.ResolutionWidth,
		Height:          &opts.ResolutionHeight,
		Port:            &opts.Port,
		ColorDepth:      &opts.ColorDepth,
		Username:        opts.Username,
		Password:        opts.Password,
		EnableWallpaper: opts.EnableWallPaper,
		EnableDrive:     opts.EnableDrive,
		CreateDrivePath: opts.CreateDrivePath,
		DrivePath:       opts.DrivePath,
	}

	data := struct {
		Name             string            `json:"name"`
		ParentIdentifier string            `json:"parentIdentifier"`
		Protocol         string            `json:"protocol"`
		Attributes       createRDPConnAttr `json:"attributes"`
		Parameters       createRDPConnConf `json:"parameters"`
	}{
		Name:             opts.Name,
		ParentIdentifier: "ROOT",
		Protocol:         "rdp",
		Attributes: createRDPConnAttr{
			MaxConn:        opts.MaxConn,
			MaxConnPerUser: opts.MaxConn,
		},
		Parameters: conf,
	}

	jsonData, _ := json.Marshal(data)

	action := func(t string) (*http.Response, error) {
		endpoint := guac.baseUrl() + "/guacamole/api/session/data/mysql/connections?token=" + t
		req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		return guac.Client.Do(req)
	}

	var out struct {
		Id string `json:"identifier"`
	}
	if err := guac.authAction("create rdp connection", action, &out); err != nil {
		return err
	}

	if err := guac.addConnectionToUser(out.Id, opts.GuacUser); err != nil {
		return err
	}

	return nil
}

// Adds newly created RDP connection to a specific Guacamole user
func (guac *Guacamole) addConnectionToUser(id string, guacuser string) error {
	data := []struct {
		Operation string `json:"op"`
		Path      string `json:"path"`
		Value     string `json:"value"`
	}{{
		Operation: "add",
		Path:      fmt.Sprintf("/connectionPermissions/%s", id),
		Value:     "READ",
	}}

	jsonData, _ := json.Marshal(data)

	action := func(t string) (*http.Response, error) {
		endpoint := fmt.Sprintf("%s/guacamole/api/session/data/mysql/users/%s/permissions?token=%s",
			guac.baseUrl(),
			guacuser,
			t)

		req, err := http.NewRequest("PATCH", endpoint, bytes.NewBuffer(jsonData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		return guac.Client.Do(req)
	}

	if err := guac.authAction("add user to connection", action, nil); err != nil {
		return err
	}

	return nil
}

// Configures a guacamole instance for environment.
// It simply changes the default password
func (guac *Guacamole) configureInstance() error {
	temp := &Guacamole{
		Client:    guac.Client,
		AdminPass: DefaultAdminPass,
		Port:      guac.Port,
	}

	var err error
	for i := 0; i < 120; i++ {
		_, err = temp.login(DefaultAdminUser, DefaultAdminPass)
		if err == nil {
			break
		}

		time.Sleep(time.Second)
	}
	if err != nil {
		return err
	}

	if err := temp.changeAdminPass(guac.AdminPass); err != nil {
		return err
	}

	return nil
}

func (guac *Guacamole) login(username, password string) (string, error) {
	content, err := guac.RawLogin(username, password)
	if err != nil {
		return "", err
	}

	var output struct {
		Message   *string `json:"message"`
		AuthToken *string `json:"authToken"`
	}

	if err := json.Unmarshal(content, &output); err != nil {
		return "", err
	}

	if output.Message != nil {
		return "", fmt.Errorf(*output.Message)
	}

	if output.AuthToken == nil {
		return "", errors.New("malformed login response")
	}

	return *output.AuthToken, nil
}

func (guac *Guacamole) RawLogin(username, password string) ([]byte, error) {
	form := url.Values{
		"username": {username},
		"password": {password},
	}

	endpoint := guac.baseUrl() + "/guacamole/api/tokens"
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := guac.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := isExpectedStatus(resp.StatusCode); err != nil {
		return nil, &GuacError{action: "login", err: err}
	}

	return ioutil.ReadAll(resp.Body)
}

func (guac *Guacamole) changeAdminPass(newPass string) error {
	action := func(t string) (*http.Response, error) {
		data := map[string]string{
			"newPassword": newPass,
			"oldPassword": guac.AdminPass,
		}

		jsonData, _ := json.Marshal(data)
		endpoint := guac.baseUrl() + "/guacamole/api/session/data/mysql/users/guacadmin/password?token=" + t
		req, err := http.NewRequest("PUT", endpoint, bytes.NewBuffer(jsonData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		return guac.Client.Do(req)
	}

	if err := guac.authAction("change admin password", action, nil); err != nil {
		return err
	}

	return nil
}

func (guac *Guacamole) GetPortFromConnectionIdentifier(connectionIdentifier string) (string, error) {
	action := func(t string) (*http.Response, error) {
		endpoint := guac.baseUrl() + "/guacamole/api/session/data/mysql/connections/" + connectionIdentifier + "/parameters?token=" + t
		log.Debug().Str("endpoint", endpoint).Msg("endpoint")
		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		return guac.Client.Do(req)
	}

	var resp struct {
		Port string `json:"port"`
	}
	if err := guac.authAction("change admin password", action, &resp); err != nil {
		return "", err
	}

	return resp.Port, nil
}

func (guac *Guacamole) baseUrl() string {
	return fmt.Sprintf("http://127.0.0.1:%d", guac.Port)
}

func isExpectedStatus(s int) error {
	if (s >= http.StatusOK) && (s <= 302) || s == http.StatusForbidden {
		return nil
	}

	return fmt.Errorf("unexpected response %d", s)
}

func (guac *Guacamole) authAction(action string, a func(string) (*http.Response, error), i interface{}) error {
	perform := func() ([]byte, int, error) {
		resp, err := a(guac.Token)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()

		content, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, 0, err
		}

		return content, resp.StatusCode, nil
	}

	shouldTryAgain := func(content []byte, status int, connErr error) (bool, error) {
		if connErr != nil {
			return true, connErr
		}

		if err := isExpectedStatus(status); err != nil {
			return true, err
		}

		if status == http.StatusForbidden {
			token, err := guac.login(DefaultAdminUser, guac.AdminPass)
			if err != nil {
				return false, err
			}

			guac.Token = token

			return true, nil
		}

		var msg struct {
			Message string `json:"message"`
		}

		if err := json.Unmarshal(content, &msg); err == nil {
			switch {
			case msg.Message == "Permission Denied.":
				token, err := guac.login(DefaultAdminUser, guac.AdminPass)
				if err != nil {
					return false, err
				}

				guac.Token = token

				return true, nil
			case msg.Message != "":
				return false, &GuacError{action: action, err: fmt.Errorf("unexpected message: %s", msg.Message)}
			}
		}

		return false, nil
	}

	var retry bool
	content, status, err := perform()
	for i := 1; i <= 3; i++ {
		retry, err = shouldTryAgain(content, status, err)
		if !retry {
			break
		}

		time.Sleep(time.Second)

		content, status, err = perform()
	}

	if err != nil {
		return err
	}

	if i != nil {
		if err := json.Unmarshal(content, i); err != nil {
			return err
		}
	}

	return nil
}

func NewGuacUserStore() *GuacUserStore {
	return &GuacUserStore{
		teams: map[string]GuacUser{},
	}
}

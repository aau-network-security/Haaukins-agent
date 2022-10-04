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

	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual/docker"
	"github.com/aau-network-security/haaukins-agent/internal/environment/lab/virtual/vbox"
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
	// TODO finish newGuac function
}

func (guac *Guacamole) create(ctx context.Context, eventTag string) error {
	_ = vbox.CreateEventFolder(eventTag)

	user := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	log.Debug().Str("user", user).Msg("starting guacd")

	containers := map[string]docker.Container{}
	containers["guacd"] = docker.NewContainer(docker.ContainerConfig{
		Image:     "guacamole/guacd:1.2.0",
		UseBridge: true,
		Labels: map[string]string{
			"hkn": "guacamole_guacd",
		},
		Mounts: []string{
			vbox.FileTransferRoot + "/" + eventTag + "/:/home/",
		},
		User: user,
	})

	mysqlPass := uuid.New().String()
	containers["db"] = docker.NewContainer(docker.ContainerConfig{
		Image: "aaunetworksecurity/guacamole-mysql",
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
	containers["web"] = docker.NewContainer(docker.ContainerConfig{
		Image: "registry.gitlab.com/haaukins/core-utils/guacamole",
		EnvVars: map[string]string{
			"MYSQL_DATABASE": "guacamole_db",
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

	if err := guac.configureInstance(); err != nil {
		closeAll()
		return err
	}

	guac.Containers = containers
	guac.Stop()

	return nil
}

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

func (guac *Guacamole) Stop() error {
	for _, container := range guac.Containers {
		if err := container.Stop(); err != nil {
			return err
		}
	}
	return nil
}

func (guac *Guacamole) Start(ctx context.Context) error {
	for _, container := range guac.Containers {
		if err := container.Start(ctx); err != nil {
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

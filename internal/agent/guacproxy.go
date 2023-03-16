package agent

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

type ProxyResponse struct {
	Message string `json:"status,omitempty"`
}

// Sets up the gin framework, and uses the cors middleware to allow from all origins. It the runs the proxy on a port specified in the agent config
func (a *Agent) RunGuacProxy() error {
	r := gin.Default()
	r.SetTrustedProxies([]string{"127.0.0.1"})
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"POST", "GET", "OPTIONS", "PUT", "DELETE"},
		AllowHeaders:     []string{"Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization", "Accept", "Origin", "Cache-Control", "X-Requested-With", "pragma", "guacamole-token", "accept-language"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	//r.Use(a.authMiddleware())

	// Load html template for guaclogin page
	r.Static("/assets", "./assets")
	r.LoadHTMLGlob("templates/*.html")

	r.Any("/guacamole/*proxyPath", a.proxy)
	r.GET("/guaclogin", a.guaclogin)

	listenAddress := fmt.Sprintf("%s:%d", a.config.ListeningIp, a.config.ProxyPort)
	return r.Run(listenAddress)
}

// The guacamole proxy handler uses the subdomain of a request like "http://test.localhost:<proxyPort>/guacamole", to guide a participant to the right guacamole
// container linked to their event. The subdomain should be the same as the event tag. It will then correlate the event tag to any running environments with the same tag
// and proxy the request the the corresponding guacamole docker container.
func (a *Agent) proxy(c *gin.Context) {
	envTag := strings.Split(c.Request.Host, ".")[0]

	env, ok := a.EnvPool.Envs[envTag]
	if !ok {
		c.JSON(http.StatusBadRequest, ProxyResponse{Message: "no guacamole for that event"})
		return
	}

	log.Debug().Uint("guacPort", env.Guac.Port).Msg("guacport for environment")
	baseGuacHost := fmt.Sprintf("http://127.0.0.1:%d", env.Guac.Port)
	guacUrl, err := url.Parse(baseGuacHost + "/guacamole")
	if err != nil {
		log.Error().Err(err).Msg("error parsing guacUrl")
		c.JSON(http.StatusInternalServerError, ProxyResponse{Message: "internal server error"})
		return
	}

	proxy := &httputil.ReverseProxy{}

	proxy.Director = func(req *http.Request) {
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.URL.Scheme = "http"
		req.URL.Host = guacUrl.Host
	}

	proxy.ServeHTTP(c.Writer, c.Request)
	return
}

// guaclogin takes two query parameters and serves a html page which runs some javascript to login the user to automatically login the user to guacamole.
func (a *Agent) guaclogin(c *gin.Context) {
	envTag := strings.Split(c.Request.Host, ".")[0]

	_, ok := a.EnvPool.Envs[envTag]
	if !ok {
		c.JSON(http.StatusBadRequest, ProxyResponse{Message: "no guacamole for that event"})
		return
	}

	username := c.Query("username")
	password := c.Query("password")
	if username == "" || password == "" {
		c.JSON(http.StatusBadRequest, ProxyResponse{Message: "Bad request"})
		return
	}
	c.HTML(http.StatusOK, "guaclogin.html", gin.H{
		"content": "This is the guaclogin page",
	})
}



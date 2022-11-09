package agent

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

type ProxyResponse struct {
	Message string `json:"status,omitempty"`
}

func (a *Agent) RunGuacProxy() error {
	r := gin.Default()
	r.SetTrustedProxies([]string{"127.0.0.1"})
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"POST", "GET", "OPTIONS", "PUT", "DELETE"},
		AllowHeaders:     []string{"Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization", "Accept", "Origin", "Cache-Control", "X-Requested-With"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	//r.Use(a.authMiddleware())

	r.Any("/guacamole", a.proxy)
	port := fmt.Sprintf(":%d", a.config.ProxyPort)
	return r.Run(port)
}

func (a *Agent) proxy(c *gin.Context) {
	envTag := strings.Split(c.Request.Host, ".")[0]

	env, ok := a.State.EnvPool.Envs[envTag]
	if !ok {
		c.JSON(http.StatusBadRequest, ProxyResponse{Message: "no guacamole for that event"})
		return
	}

	log.Debug().Uint("guacPort", env.Guac.Port)
	c.JSON(200, ProxyResponse{Message: "success"})
	return
	//envTag := strings.Split(c.Get("location").string)
	//url := fmt.Sprintf("http://")
	//remote, err := url.Parse()
}

func (a *Agent) jwtExtract(c *gin.Context) string {
	token := c.GetHeader("Authorization")
	log.Debug().Msgf("Using secret key: %s", a.config.JwtSecret)
	return token
}

func (a *Agent) jwtVerify(c *gin.Context) (*jwt.Token, error) {
	tokenString := a.jwtExtract(c)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(a.config.JwtSecret), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (a *Agent) jwtValidate(c *gin.Context) (jwt.MapClaims, error) {
	token, err := a.jwtVerify(c)
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		log.Printf("Invalid JWT Token")
		return nil, errors.New("token invalid")
	}
}

func (a *Agent) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := a.jwtValidate(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, ProxyResponse{Message: "Invalid JWT"})
			return
		}
		// Passing jwt claims to next handler function in the gin context
		c.Set("jti", claims["jti"])
		c.Set("exp", claims["exp"])
		c.Set("sub", claims["sub"])
		c.Next()
	}
}

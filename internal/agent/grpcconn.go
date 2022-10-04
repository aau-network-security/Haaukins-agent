package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	eproto "github.com/aau-network-security/haaukins-exercises/proto"
	"github.com/dgrijalva/jwt-go"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

const (
	NoTokenErrMsg     = "token contains an invalid number of segments"
	UnauthorizeErrMsg = "unauthorized"
)

var (
	UnreachableDBErr = errors.New("Database seems to be unreachable")
	UnauthorizedErr  = errors.New("You seem to not be logged in")
)



type Creds struct {
	Token    string
	Insecure bool
}

func (c Creds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{
		"token": string(c.Token),
	}, nil
}

func (c Creds) RequireTransportSecurity() bool {
	return !c.Insecure
}

func enableClientCertificates() credentials.TransportCredentials {
	// Load the client certificates from disk
	pool, _ := x509.SystemCertPool()

	creds := credentials.NewTLS(&tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12, // disable TLS 1.0 and 1.1
		CipherSuites: []uint16{ // only enable secure algorithms for TLS 1.2
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	})

	return creds
}

func TranslateRPCErr(err error) error {
	st, ok := status.FromError(err)
	if ok {
		msg := st.Message()
		switch {
		case UnauthorizeErrMsg == msg:
			return UnauthorizedErr

		case NoTokenErrMsg == msg:
			return UnauthorizedErr

		case strings.Contains(msg, "TransientFailure"):
			return UnreachableDBErr
		}

		return err
	}

	return err
}

// Creating credentials for grpc connection
func constructAuthCreds(authKey, signKey string) (Creds, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		AUTH_KEY: authKey,
	})
	tokenString, err := token.SignedString([]byte(signKey))
	if err != nil {
		return Creds{}, TranslateRPCErr(err)
	}
	authCreds := Creds{Token: tokenString}
	return authCreds, nil
}

// NewExerciseClientConn does not require CA file to communicate
// due to the fact that a script is running on Gitlab CI to push
// exercises to the service
func NewExerciseClientConn(config ServiceConfig) (eproto.ExerciseStoreClient, error) {
	creds := enableClientCertificates()
	authCreds, err := constructAuthCreds(config.AuthKey, config.SignKey)
	if err != nil {
		return nil, fmt.Errorf("[exercise-service]: Error in constructing auth credentials %v", err)
	}
	if config.TLSEnabled {
		log.Debug().Bool("TLS", config.TLSEnabled).Msg("TLS for exercise service is enabled, creating secure connection...")
		dialOpts := []grpc.DialOption{
			grpc.WithTransportCredentials(creds),
			grpc.WithPerRPCCredentials(authCreds),
			grpc.WithBlock(),
			grpc.WithReturnConnectionError(),
			grpc.WithTimeout(time.Second * 3),
		}
		conn, err := grpc.Dial(config.Grpc, dialOpts...)
		if err != nil {
			return nil, TranslateRPCErr(err)
		}
		client := eproto.NewExerciseStoreClient(conn)
		return client, nil
	}
	authCreds.Insecure = true
	conn, err := grpc.Dial(config.Grpc, grpc.WithInsecure(), grpc.WithPerRPCCredentials(authCreds))
	if err != nil {
		return nil, TranslateRPCErr(err)
	}
	client := eproto.NewExerciseStoreClient(conn)
	return client, nil
}

package main

import (
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"time"

	dcontext "github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/api/errcode"
	"github.com/docker/distribution/registry/auth"
	_ "github.com/docker/distribution/registry/auth/htpasswd"
	"github.com/docker/libtrust"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	enforceRepoClass bool
)

func main() {
	if err := run(); err != nil {
		logrus.Fatalf("error: %+v", err)
	}
}
func run() error {
	var (
		issuer = &TokenIssuer{}
		pkFile string
		addr   string
		debug  bool
		err    error

		passwdFile string
		cfgFile    string

		cert    string
		certKey string
	)

	flag.StringVar(&issuer.Issuer, "issuer", "distribution-token-server", "Issuer string for token")
	flag.StringVar(&pkFile, "key", "", "Private key file")
	flag.StringVar(&addr, "addr", "0.0.0.0:8080", "Address to listen on")
	flag.BoolVar(&debug, "debug", false, "Debug mode")

	flag.StringVar(&passwdFile, "passwd", "", "Static accounts file")
	flag.StringVar(&cfgFile, "config", "", "Config file")

	flag.StringVar(&cert, "tlscert", "", "Certificate file for TLS")
	flag.StringVar(&certKey, "tlskey", "", "Certificate key for TLS")

	//	flag.BoolVar(&enforceRepoClass, "enforce-class", false, "Enforce policy for single repository class")

	flag.Parse()

	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if pkFile == "" {
		return errors.Errorf("private key required")
	}
	issuer.SigningKey, err = libtrust.LoadKeyFile(pkFile)
	if err != nil {
		return errors.Wrapf(err, "failed to load private key from %s", pkFile)
	}
	logrus.Debugf("Loaded private key with id %s", issuer.SigningKey.KeyID())

	pa, err := ReadPasswdConfig(passwdFile)
	if err != nil {
		return err
	}

	cfg, err := ReadConfig(cfgFile)
	if err != nil {
		return err
	}

	// TODO: Make configurable
	issuer.Expiration = 15 * time.Minute

	ts := &tokenServer{
		issuer: issuer,
		pa:     pa,
		cfg:    cfg,
	}

	router := mux.NewRouter()
	router.Path("/token/").Methods("GET").Handler(handlerWithContext(ts.getToken))
	router.Path("/token/").Methods("POST").Handler(handlerWithContext(ts.postToken))

	router.Path("/token/newsession").Methods("POST").Handler(handlerWithContext(ts.newSession))
	router.Path("/token/credentials").Methods("POST").Handler(handlerWithContext(ts.newCredentials))

	if cert == "" {
		return http.ListenAndServe(addr, router)
	} else if certKey == "" {
		return errors.Errorf("Must provide certficate (-tlscert) and key (-tlskey)")
	} else {
		return http.ListenAndServeTLS(addr, cert, certKey, router)
	}
}

func handlerWithContext(handler func(context.Context, http.ResponseWriter, *http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := handler(r.Context(), w, r); err != nil {
			if err := errcode.ServeJSON(w, err); err != nil {
				logrus.Errorf("error sending error response: %v", err)
			}
			logrus.Debugf("handler error: %+v", err)
		}
	})
}

type tokenServer struct {
	issuer *TokenIssuer
	pa     *PasswdAuth
	cfg    map[string]*ScopeConfig
}

// getToken handles authenticating the request and authorizing access to the
// requested scopes.
func (ts *tokenServer) getToken(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	params := r.URL.Query()
	service := params.Get("service")
	scopeSpecifiers := params["scope"]

	requestedAccessList := ResolveScopeSpecifiers(ctx, scopeSpecifiers)

	username, pw, _ := r.BasicAuth()

	grantedAccessList := ts.authorize(username, pw, requestedAccessList)

	token, err := ts.issuer.CreateJWT(username, service, grantedAccessList)
	if err != nil {
		return err
	}

	response := tokenResponse{
		Token:     token,
		ExpiresIn: int(ts.issuer.Expiration.Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	logrus.Info("get token complete")
	return nil
}

func (ts *tokenServer) authorize(user, pw string, access []auth.Access) []auth.Access {
	pulls, rest := AllowPulls(access)
	byPw, rest := ts.pa.Authorize(user, pw, rest)
	granted := append(pulls, byPw...)
	for _, sc := range ts.cfg {
		allow, deny := sc.b.Authorize(user, pw, rest)
		granted = append(granted, allow...)
		rest = deny
	}
	logrus.Debugf("granted %+v, rest %+v", granted, rest)
	return granted
}

type postTokenResponse struct {
	Token        string `json:"access_token"`
	Scope        string `json:"scope,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	IssuedAt     string `json:"issued_at,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// postToken handles authenticating the request and authorizing access to the
// requested scopes.
func (ts *tokenServer) postToken(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	grantType := r.PostFormValue("grant_type")
	if grantType == "" {
		return ErrorMissingRequiredField.WithDetail("missing grant_type value")
	}

	service := r.PostFormValue("service")
	if service == "" {
		return ErrorMissingRequiredField.WithDetail("missing service value")
	}

	clientID := r.PostFormValue("client_id")
	if clientID == "" {
		return ErrorMissingRequiredField.WithDetail("missing client_id value")
	}

	requestedAccessList := ResolveScopeList(ctx, r.PostFormValue("scope"))
	var grantedAccessList []auth.Access

	var subject string
	switch grantType {
	case "password":
		subject = r.PostFormValue("username")
		if subject == "" {
			return ErrorUnsupportedValue.WithDetail("missing username value")
		}
		password := r.PostFormValue("password")
		if password == "" {
			return ErrorUnsupportedValue.WithDetail("missing password value")
		}
		grantedAccessList = ts.authorize(subject, password, requestedAccessList)
	default:
		return ErrorUnsupportedValue.WithDetail("unknown grant_type value")
	}

	token, err := ts.issuer.CreateJWT(subject, service, grantedAccessList)
	if err != nil {
		return err
	}

	dcontext.GetLogger(ctx).Info("authorized client")

	response := postTokenResponse{
		Token:     token,
		ExpiresIn: int(ts.issuer.Expiration.Seconds()),
		IssuedAt:  time.Now().UTC().Format(time.RFC3339),
		Scope:     ToScopeList(grantedAccessList),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	logrus.Info("post token complete")
	return nil
}

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

func (ts *tokenServer) newSession(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	scope := r.PostFormValue("scope")
	if scope == "" {
		return ErrorMissingRequiredField.WithDetail("missing scope")
	}

	sc, ok := ts.cfg[scope]
	if !ok {
		return errors.Errorf("invalid scope")
	}
	b := sc.b

	if err := b.ValidateRequest(ctx, r); err != nil {
		return err
	}

	jobID := r.PostFormValue("jobid")
	if jobID == "" {
		return ErrorMissingRequiredField.WithDetail("missing jobid value")
	}

	session, err := b.NewSession(ctx, jobID)
	if err != nil {
		return err
	}

	w.WriteHeader(200)
	_, err = fmt.Fprintf(w, "%s %s", session.SessionID(), session.Uniq())
	return err
}

func (ts *tokenServer) newCredentials(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	scope := r.PostFormValue("scope")
	if scope == "" {
		return ErrorMissingRequiredField.WithDetail("missing scope")
	}

	sc, ok := ts.cfg[scope]
	if !ok {
		return errors.Errorf("invalid scope")
	}
	b := sc.b

	if err := b.ValidateRequest(ctx, r); err != nil {
		return err
	}

	sessionID := r.PostFormValue("sessionid")
	if sessionID == "" {
		return ErrorMissingRequiredField.WithDetail("missing sessionid value")
	}
	u, pw, err := b.Credentials(ctx, sessionID)
	if err != nil {
		return err
	}
	type auth struct {
		Auth string `json:"auth"`
	}
	var config = struct {
		Auths map[string]auth `json:"auths"`
	}{
		Auths: map[string]auth{
			sc.Registry: {
				Auth: base64.StdEncoding.EncodeToString([]byte(u + ":" + pw)),
			},
		},
	}
	dt, err := json.Marshal(config)
	if err != nil {
		return err
	}
	w.WriteHeader(200)
	_, err = w.Write(dt)
	return err
}

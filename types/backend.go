package types

import (
	"context"
	"net/http"

	"github.com/docker/distribution/registry/auth"
)

type Session interface {
	SessionID() string
	Uniq() string
}

type Backend interface {
	ValidateRequest(ctx context.Context, req *http.Request) error
	NewSession(ctx context.Context, jobID string) (Session, error)
	Credentials(ctx context.Context, sessionID string) (string, string, error)
	Authorize(u, pw string, access []auth.Access) ([]auth.Access, []auth.Access)
	//TryClean(ctx context.Context, sessionID string) (bool, error)
}

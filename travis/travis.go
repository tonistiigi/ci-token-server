package travis

import (
	"context"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/docker/distribution/registry/auth"
	"github.com/moby/buildkit/identity"
	"github.com/pkg/errors"
	"github.com/tonistiigi/ci-token-server/types"
)

type Travis struct {
	repo  string
	scope string
	mu    sync.Mutex
	m     map[string]*Session
}

func New(scope, repo string) (*Travis, error) {
	t := &Travis{
		repo:  repo,
		scope: scope,
		m:     map[string]*Session{},
	}
	return t, nil
}

type Session struct {
	buildID   string
	sessionID string
	uniq      string
	pw        string
	jobID     string
}

func (s *Session) SessionID() string {
	return s.sessionID
}

func (s *Session) Uniq() string {
	return s.uniq
}

func (t *Travis) ValidateRequest(ctx context.Context, req *http.Request) error {
	ip := req.RemoteAddr
	if os.Getenv("ALLOW_PROXY_REQUESTS") == "1" {
		if fwdAddress := req.Header.Get("X-Forwarded-For"); fwdAddress != "" {
			ip = fwdAddress
		}
	}
	if err := validateTravisIP(ctx, ip); err != nil {
		return err
	}
	return nil
}

func (t *Travis) NewSession(ctx context.Context, jobID string) (types.Session, error) {
	st, err := getJobInfo(ctx, jobID)
	if err != nil {
		return nil, err
	}

	if st.Status != "started" {
		return nil, errors.Errorf("invalid status %s", st.Status)
	}
	if st.Repo != t.repo {
		return nil, errors.Errorf("repository %s not allowed", st.Repo)
	}

	s := &Session{
		sessionID: jobID + "_" + identity.NewID()[:10],
		uniq:      ">>auth-proof:" + identity.NewID() + "<<",
		pw:        identity.NewID(),
		jobID:     jobID,
		buildID:   st.BuildID,
	}
	t.mu.Lock()
	t.m[s.sessionID] = s
	t.mu.Unlock()
	go func() {
		for {
			<-time.After(5 * time.Minute)
			b, err := t.tryClean(context.TODO(), s.sessionID)
			if b || err != nil {
				return
			}
		}
	}()
	return s, nil
}

func (r *Travis) Credentials(ctx context.Context, sessionID string) (string, string, error) {
	r.mu.Lock()
	s, ok := r.m[sessionID]
	r.mu.Unlock()
	if !ok {
		return "", "", errors.Errorf("invalid sessionid")
	}

	st, err := getJobInfo(ctx, s.jobID)
	if err != nil {
		return "", "", err
	}

	if st.Status != "started" {
		return "", "", errors.Errorf("invalid status %s", st.Status)
	}

	if err := waitMessageInJob(ctx, s.jobID, s.uniq, 2*time.Minute); err != nil {
		return "", "", err
	}

	return sessionID, s.pw, nil
}

func (r *Travis) Authorize(u, pw string, access []auth.Access) (valid, rest []auth.Access) {
	r.mu.Lock()
	s, ok := r.m[u]
	r.mu.Unlock()
	if !ok || pw != s.pw {
		return nil, access
	}

	st, err := getJobInfo(context.TODO(), s.jobID)
	if err != nil {
		return nil, access
	}

	if st.Status != "started" {
		return nil, access
	}

	for _, a := range access {
		if a.Type == "repository" && a.Name == r.scope+s.buildID {
			valid = append(valid, a)
		} else {
			rest = append(rest, a)
		}
	}
	return
}

func (r *Travis) tryClean(ctx context.Context, sessionID string) (bool, error) {
	r.mu.Lock()
	s, ok := r.m[sessionID]
	if !ok {
		r.mu.Unlock()
		return false, errors.Errorf("invalid sessionid")
	}
	defer r.mu.Unlock()
	st, err := getJobInfo(context.TODO(), s.jobID)
	if err != nil {
		return false, err
	}
	if st.Status != "started" {
		delete(r.m, sessionID)
		return true, nil
	}
	return false, nil
}

package travis

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
)

var ipMap map[string]struct{}
var ipLock sync.Mutex
var nextIPCheck <-chan time.Time

func validateTravisIP(ctx context.Context, remoteAddr string) error {
	ipLock.Lock()
	defer ipLock.Unlock()

	c := nextIPCheck
	if c == nil {
		c2 := make(chan time.Time)
		close(c2)
		c = (<-chan time.Time)(c2)
	}
	select {
	case <-c:
		req, err := http.NewRequest("GET", "https://dnsjson.com/nat.travisci.net/A.json", nil)
		if err != nil {
			return err
		}
		req = req.WithContext(ctx)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return errors.Wrap(err, "failed to query ip range")
		}
		var parsed struct {
			Results struct {
				Records []string
			}
		}
		if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
			return errors.Wrap(err, "failed to parse IP range")
		}
		ipMap = map[string]struct{}{}
		for _, ip := range parsed.Results.Records {
			ipMap[ip] = struct{}{}
		}
		nextIPCheck = time.NewTimer(time.Hour).C
	default:
	}

	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		if strings.Contains(err.Error(), "missing port in address") {
			ip = remoteAddr
		} else {
			return errors.Wrapf(err, "invalid remoteAddr %v", remoteAddr)
		}
	}
	_, ok := ipMap[ip]
	if !ok {
		return errors.Errorf("forbidden ip")
	}
	return nil
}

type jobStatus struct {
	BuildID string
	Repo    string
	Status  string
}

func getJobInfo(ctx context.Context, jobID string) (*jobStatus, error) {
	req, err := http.NewRequest("GET", "https://api.travis-ci.org/v3/job/"+jobID, nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to query ip range")
	}
	var parsed struct {
		State      string
		Repository struct {
			Slug string
		}
		Build struct {
			ID int
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, errors.Wrap(err, "failed to parse job")
	}
	return &jobStatus{
		BuildID: strconv.Itoa(parsed.Build.ID),
		Repo:    parsed.Repository.Slug,
		Status:  parsed.State,
	}, nil
}

func checkMessageInJob(ctx context.Context, jobID, msg string) (bool, error) {
	req, err := http.NewRequest("GET", "https://api.travis-ci.org/v3/job/"+jobID+"/log.txt", nil)
	if err != nil {
		return false, err
	}
	req = req.WithContext(ctx)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, errors.Wrap(err, "failed to query ip range")
	}
	s := bufio.NewScanner(resp.Body)
	for s.Scan() {
		if strings.Contains(s.Text(), msg) {
			return true, nil
		}
	}
	return false, nil
}

func waitMessageInJob(ctx context.Context, jobID, msg string, timeout time.Duration) error {
	ch := make(chan time.Time)
	close(ch)
	next := (<-chan time.Time)(ch)
	tm := time.After(timeout)
	backoff := 500 * time.Millisecond
	for {
		select {
		case <-tm:
			return errors.Errorf("timeout")
		case <-next:
		}
		ok, err := checkMessageInJob(ctx, jobID, msg)
		if err == nil && ok {
			return nil
		}
		next = time.NewTimer(backoff).C
		backoff *= 2
	}
}

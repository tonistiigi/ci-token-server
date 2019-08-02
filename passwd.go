package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/docker/distribution/registry/auth"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

type PasswdAuth struct {
	Config map[string]PasswdAccess
}

type PasswdAccess struct {
	Hash  []byte
	Scope []string
}

func ReadPasswdConfig(fp string) (*PasswdAuth, error) {
	if fp == "" {
		return &PasswdAuth{}, nil
	}
	var pa PasswdAuth
	f, err := os.Open(fp)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open %s", fp)
	}
	if err := json.NewDecoder(f).Decode(&pa.Config); err != nil {
		return nil, err
	}
	f.Close()
	return &pa, nil
}

func (pa *PasswdAuth) Authorize(user, pw string, access []auth.Access) (valid, rest []auth.Access) {
	u, ok := pa.Config[user]
	if !ok {
		return nil, access
	}
	if err := bcrypt.CompareHashAndPassword(u.Hash, []byte(pw)); err != nil {
		return nil, access
	}
	for _, a := range access {
		found := false
		if a.Type == "repository" {
			for _, s := range u.Scope {
				if m, err := filepath.Match(s, a.Name); err == nil && m {
					found = true
					break
				}
			}
		}
		if found {
			valid = append(valid, a)
		} else {
			rest = append(rest, a)
		}
	}
	return valid, rest
}

func AllowPulls(access []auth.Access) (valid, rest []auth.Access) {
	for _, a := range access {
		if a.Type == "repository" && a.Action == "pull" {
			valid = append(valid, a)
		} else {
			rest = append(rest, a)
		}
	}
	return
}

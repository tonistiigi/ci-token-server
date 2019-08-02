package main

import (
	"encoding/json"
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tonistiigi/ci-token-server/travis"
	"github.com/tonistiigi/ci-token-server/types"
)

type ScopeConfig struct {
	Backend    string
	Registry   string
	SourceRepo string
	b          types.Backend
}

func ReadConfig(fp string) (map[string]*ScopeConfig, error) {
	if fp == "" {
		return nil, nil
	}
	var cfg map[string]*ScopeConfig
	f, err := os.Open(fp)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open %s", fp)
	}
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}
	f.Close()
	for name, sc := range cfg {
		switch sc.Backend {
		case "travis":
			t, err := travis.New(name, sc.SourceRepo)
			if err != nil {
				return nil, err
			}
			sc.b = t
		default:
			return nil, errors.Errorf("invalid backend %s", sc.Backend)
		}
		logrus.Debugf("loaded %s: %s %s %s", name, sc.Backend, sc.Registry, sc.SourceRepo)
	}
	logrus.Debugf("loaded %d scopes", len(cfg))
	return cfg, nil
}

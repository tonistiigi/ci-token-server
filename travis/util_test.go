package travis

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTravisIP(t *testing.T) {
	err := validateTravisIP(context.TODO(), "34.66.200.49")
	require.NoError(t, err)
	err = validateTravisIP(context.TODO(), "1.2.3.4")
	require.Error(t, err)
	err = validateTravisIP(context.TODO(), "104.154.113.151")
	require.NoError(t, err)
}

func TestTravisInfo(t *testing.T) {
	st, err := getJobInfo(context.TODO(), "566084222")
	require.NoError(t, err)
	require.Equal(t, st.BuildID, "566084221")
	require.Equal(t, st.Status, "passed")
	require.Equal(t, st.Repo, "moby/buildkit")
}

func TestTravisMessage(t *testing.T) {
	err := waitMessageInJob(context.TODO(), "566084222", "docker.io/library/golang:1.12-buster", 5*time.Second)
	require.NoError(t, err)
}

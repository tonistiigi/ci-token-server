#syntax=docker/dockerfile-upstream:1.1-experimental
from golang:1.12-alpine as build
run apk add --no-cache file
workdir /src
copy . .
env GOFLAGS=-mod=vendor CGO_ENABLED=0
run --mount=type=cache,target=/root/.cache go build -o /usr/bin/token-server . && \
     file /usr/bin/token-server | grep "statically linked"

from alpine
run apk add --no-cache ca-certificates
copy --from=build /usr/bin/token-server /usr/bin/token-server
entrypoint ["/usr/bin/token-server"]
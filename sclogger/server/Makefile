# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

all: server

run:
	go run server.go

# Build server binary
server:
	go build -o logserver server.go

# Build the docker image
docker-build: server
	docker build . -t ${IMG}

# Push the docker image
docker-push:
	docker push ${IMG}

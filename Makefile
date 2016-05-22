# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOINSTALL=$(GOCMD) install
GOTEST=$(GOCMD) test
GODEP=$(GOTEST) -i
GOFMT=gofmt -w

all:
	$(GOBUILD) -o ./bin/actuary ./cmd/actuary
	protoc -I/usr/local/include -I. -I$(GOPATH)/src -I$(GOPATH)/src/github.com/gengo/grpc-gateway/third_party/googleapis --go_out=Mgoogle/api/annotations.proto=github.com/gengo/grpc-gateway/third_party/googleapis/google/api,plugins=grpc:. ./protos/actuary.proto
	protoc -I/usr/local/include -I. -I$(GOPATH)/src -I$(GOPATH)/src/github.com/gengo/grpc-gateway/third_party/googleapis --grpc-gateway_out=logtostderr=true:. ./protos/actuary.proto
	$(GOBUILD) -o ./bin/actuary-server ./cmd/actuary-server

clean:
	rm -f bin/*


package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"

	"golang.org/x/net/context"

	"github.com/diogomonica/actuary/protos"
	"github.com/gengo/grpc-gateway/runtime"
	"github.com/golang/glog"
	"google.golang.org/grpc"
)

var (
	profileEndpoint = flag.String("profile_endpoint", "localhost:9090", "endpoint of ProfileService")
)

type profileServer struct{}

func newProfileServer() actuary.ProfileServiceServer {
	return new(profileServer)
}

func (s *profileServer) GetProfile(ctx context.Context, msg *actuary.ProfileHash) (*actuary.Profile, error) {
	fmt.Printf("InsideGetProfile\n")
	glog.Info(msg)
	return &actuary.Profile{Profile: []byte{0x1}}, nil
}

func (s *profileServer) StoreProfile(ctx context.Context, msg *actuary.Profile) (*actuary.Empty, error) {
	fmt.Printf("InsideStoreProfile\n")
	glog.Info(msg)
	return &actuary.Empty{}, nil
}

func ServerRun() error {
	l, err := net.Listen("tcp", ":9090")
	if err != nil {
		return err
	}
	s := grpc.NewServer()
	actuary.RegisterProfileServiceServer(s, newProfileServer())
	s.Serve(l)
	return nil
}

func ProxyRun(address string, opts ...runtime.ServeMuxOption) error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := runtime.NewServeMux(opts...)
	dialOpts := []grpc.DialOption{grpc.WithInsecure()}
	err := actuary.RegisterProfileServiceHandlerFromEndpoint(ctx, mux, *profileEndpoint, dialOpts)
	if err != nil {
		return err
	}

	http.ListenAndServe(address, mux)
	return nil
}

func main() {
	flag.Parse()
	defer glog.Flush()

	go func() {
		if err := ProxyRun(":8080"); err != nil {
			glog.Fatal(err)
		}
	}()

	if err := ServerRun(); err != nil {
		glog.Fatal(err)
	}
}

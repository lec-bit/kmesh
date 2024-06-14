package security

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/agiledragon/gomonkey/v2"
	pb "istio.io/api/security/v1alpha1"
	istiogrpc "istio.io/istio/pilot/pkg/grpc"
	testutil "istio.io/istio/pilot/test/util"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/monitoring/monitortest"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/spiffe"
	"istio.io/istio/security/pkg/credentialfetcher/plugin"
	"istio.io/istio/security/pkg/monitoring"

	"kmesh.net/kmesh/pkg/nets"
)

const (
	mockServerAddress = "localhost:0"
)

var (
	fakeCert          = []string{"foo", "bar"}
)

type mockCAServer struct {
	pb.UnimplementedIstioCertificateServiceServer
	Certs         []string
	Authenticator *security.FakeAuthenticator
	Err           error
}

func (ca *mockCAServer) CreateCertificate(ctx context.Context, in *pb.IstioCertificateRequest) (*pb.IstioCertificateResponse, error) {
	if ca.Err == nil {
		return &pb.IstioCertificateResponse{CertChain: ca.Certs}, nil
	}
	return nil, ca.Err
}

func tlsOption(t *testing.T) grpc.ServerOption {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(
		filepath.Join("./testdata/cert-chain.pem"),
		filepath.Join("./testdata/key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	peerCertVerifier := spiffe.NewPeerCertVerifier()
	if err := peerCertVerifier.AddMappingFromPEM("cluster.local",
		testutil.ReadFile(t, filepath.Join("./testdata/root-cert.pem"))); err != nil {
		t.Fatal(err)
	}
	return grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    peerCertVerifier.GetGeneralCertPool(),
		MinVersion:   tls.VersionTLS12,
	}))
}

func serve(t *testing.T, ca mockCAServer, opts ...grpc.ServerOption) string {
	// create a local grpc server
	s := grpc.NewServer(opts...)
	t.Cleanup(s.Stop)
	lis, err := net.Listen("tcp", mockServerAddress)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	go func() {
		pb.RegisterIstioCertificateServiceServer(s, &ca)
		if err := s.Serve(lis); err != nil {
			t.Logf("failed to serve: %v", err)
		}
	}()
	_, port, _ := net.SplitHostPort(lis.Addr().String())
	return fmt.Sprintf("localhost:%s", port)
}

// GrpcConnect creates a client connection to the given addr
func GrpcConnect(addr string, RootCert string) (*grpc.ClientConn, error) {
	var (
		err  error
		conn *grpc.ClientConn
		tlsOptions *istiogrpc.TLSOptions
	)

	if RootCert == "" {
		tlsOptions = nil
	}else {
		tlsOptions = &istiogrpc.TLSOptions{
			RootCert:      RootCert,
			ServerAddress: addr,
		}
	}
	
	opts, err := istiogrpc.ClientOptions(nil, tlsOptions)
	if err != nil {
		return nil, err
	}

	if conn, err = grpc.Dial(addr, opts...); err != nil {
		return nil, err
	}

	return conn, nil
}

func TestCitadelClientRotation(t *testing.T) {
	checkSign := func(t *testing.T, cli CaClient, expectError bool) {
		t.Helper()
		identity := "spiffe:///ns/default/sa/default"
		resp, err := cli.CsrSend([]byte{0o1}, 1, identity)
		if expectError != (err != nil) {
			t.Fatalf("expected error:%v, got error:%v", expectError, err)
		}
		if !expectError && !reflect.DeepEqual(resp, fakeCert) {
			t.Fatalf("expected cert: %v", resp)
		}
	}

	certDir := filepath.Join("./testdata")
	t.Run("cert always present", func(t *testing.T) {
		server := mockCAServer{Certs: fakeCert, Err: nil, Authenticator: security.NewFakeAuthenticator("ca")}
		address := serve(t, server, tlsOption(t))
		opts := &security.Options{
			CredFetcher: plugin.CreateTokenPlugin("testdata/token"),
			ProvCert:    certDir,
		}
		rootCert := path.Join(certDir, constants.RootCertFilename)
		key := path.Join(certDir, constants.KeyFilename)
		cert := path.Join(certDir, constants.CertChainFilename)
		tlsOpts := &tlsOptions{
			RootCert: rootCert,
			Key:      key,
			Cert:     cert,
		}

		patches := gomonkey.NewPatches()
		patches.ApplyFunc(nets.GrpcConnect, func(addr string) (*grpc.ClientConn, error){
			return GrpcConnect(address, rootCert)
		}) 
		defer func() {
			patches.Reset()
		}()
		
		cli, err := newCaClient(opts, tlsOpts)
		if err != nil {
			t.Errorf("failed to create ca client: %v", err)
		}
		t.Cleanup(func() {
			_ = cli.Close()
		})
		
		server.Authenticator.Set("fake", "")
		checkSign(t, cli, false)
		// Expiring the token is harder, so just switch to only allow certs
		server.Authenticator.Set("", "istiod.istio-system.svc")
		checkSign(t, cli, false)
		checkSign(t, cli, false)
		checkSign(t, cli, false)
	})
}

func TestCaClient(t *testing.T) {
	testCases := map[string]struct {
		server       mockCAServer
		expectedCert []string
		expectedErr  string
		expectRetry  bool
	}{
		"Valid certs": {
			server:       mockCAServer{Certs: fakeCert, Err: nil},
			expectedCert: fakeCert,
			expectedErr:  "",
		},
		"Empty response": {
			server:       mockCAServer{Certs: []string{}, Err: nil},
			expectedCert: nil,
			expectedErr:  "invalid empty CertChain",
		},
	}

	for id, tc := range testCases {
		t.Run(id, func(t *testing.T) {
			mt := monitortest.New(t)
			address := serve(t, tc.server)

			patches := gomonkey.NewPatches()
			patches.ApplyFunc(nets.GrpcConnect, func(addr string) (*grpc.ClientConn, error){
				return GrpcConnect(address, "")
			})
			defer func() {
				patches.Reset()
			}()

			cli, err := newCaClient(nil, nil)
			if err != nil {
				t.Errorf("failed to create ca client: %v", err)
			}
			t.Cleanup(func() {
				_ = cli.Close()
			})
			

			identity := "spiffe:///ns/default/sa/default"
			resp, err := cli.CsrSend([]byte{0o1}, 1, identity)
			if err != nil {
				if !strings.Contains(err.Error(), tc.expectedErr) {
					t.Errorf("error (%s) does not match expected error (%s)", err.Error(), tc.expectedErr)
				}
			} else {
				if tc.expectedErr != "" {
					t.Errorf("expect error: %s but got no error", tc.expectedErr)
				} else if !reflect.DeepEqual(resp, tc.expectedCert) {
					t.Errorf("resp: got %+v, expected %v", resp, tc.expectedCert)
				}
			}
			if tc.expectRetry {
				mt.Assert("num_outgoing_retries", map[string]string{"request_type": monitoring.CSR}, monitortest.AtLeast(1))
			}
		})
	}
}
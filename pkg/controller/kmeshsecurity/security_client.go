/*
 * Copyright 2024 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package kmeshsecurity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/structpb"
	pb "istio.io/api/security/v1alpha1"
	"istio.io/istio/pkg/env"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/spiffe"
	nodeagentutil "istio.io/istio/security/pkg/nodeagent/util"
	pkiutil "istio.io/istio/security/pkg/pki/util"
	"kmesh.net/kmesh/pkg/controller/workload"
	"kmesh.net/kmesh/pkg/nets"
)
 
 var tlsOpts *TLSOptions 
 type CitadelClient struct {
	 // It means enable tls connection to Citadel if this is not nil.
	 tlsOpts  *TLSOptions
	 client   pb.IstioCertificateServiceClient
	 conn     *grpc.ClientConn
	 //provider *TokenProvider
	 opts     *security.Options
 }
 
 // NewCitadelClient create a CA client for Citadel.
 func NewCitadelClient(opts *security.Options, tlsOpts *TLSOptions) (*CitadelClient, error) {
	 var err error;
 
	 c := &CitadelClient{
		 tlsOpts:  tlsOpts,
		 opts:     opts,
		// provider: NewCATokenProvider(opts),
	 }
	 CSRSignAddress := env.Register("MESH_CONTROLLER", "istiod.istio-system.svc:15012", "").Get()
	 conn, err := nets.GrpcConnect(CSRSignAddress);
	 if err != nil {
		 log.Errorf("Failed to connect to endpoint %s: %v", opts.CAEndpoint, err)
		 return nil, fmt.Errorf("failed to connect to endpoint %s", opts.CAEndpoint)
	 }
 
	 c.conn = conn
	 c.client = pb.NewIstioCertificateServiceClient(conn)
	 return c, nil
 }
 
 //func NewCATokenProvider(opts *security.Options) *TokenProvider {
//	 return &TokenProvider{opts, true}
 //}
 
 // TokenProvider is a grpc PerRPCCredentials that can be used to attach a JWT token to each gRPC call.
 // TokenProvider can be used for XDS, which may involve token exchange through STS.
 //type TokenProvider struct {
//	 opts *security.Options
	 // TokenProvider can be used for XDS. Because CA is often used with
	 // external systems and XDS is not often (yet?), many of the security options only apply to CA
	 // communication. A more proper solution would be to have separate options for CA and XDS, but
	 // this requires API changes.
//	 forCA bool
 //}
 
 type TLSOptions struct {
	RootCert string
	Key      string
	Cert     string
}

// CSRSign calls Citadel to sign a CSR.
func (c *CitadelClient) CSRSign(csrPEM []byte, certValidTTLInSec int64) (res []string, err error) {
	crMetaStruct := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			security.CertSigner: {
				Kind: &structpb.Value_StringValue{StringValue: c.opts.CertSigner},
			},
		},
	}
	req := &pb.IstioCertificateRequest{
		Csr:              string(csrPEM),
		ValidityDuration: certValidTTLInSec,
		Metadata:         crMetaStruct,
	}

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("ClusterID", c.opts.ClusterID))
	resp, err := c.client.CreateCertificate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %v", err)
	}

	if len(resp.CertChain) <= 1 {
		return nil, errors.New("invalid empty CertChain")
	}

	return resp.CertChain, nil
}

// concatCerts concatenates PEM certificates, making sure each one starts on a new line
func concatCerts(certsPEM []string) []byte {
	if len(certsPEM) == 0 {
		return []byte{}
	}
	var certChain bytes.Buffer
	for i, c := range certsPEM {
		certChain.WriteString(c)
		if i < len(certsPEM)-1 && !strings.HasSuffix(c, "\n") {
			certChain.WriteString("\n")
		}
	}
	return certChain.Bytes()
}

func (c *CitadelClient) fetch_cert(uid string) (secret *security.SecretItem, err error) {
	var rootCertPEM []byte
	
	workloadCache := workload.GetCacheByUid(uid)
	csrHostName := &spiffe.Identity{
		TrustDomain:    workloadCache.TrustDomain, 
		Namespace:      workloadCache.Namespace, 
		ServiceAccount: workloadCache.Name,
	}
	log.Debugf("constructed host name for CSR: %s", csrHostName.String())
 
	options := pkiutil.CertOptions{
		Host:       csrHostName.String(),
		RSAKeySize: c.opts.WorkloadRSAKeySize,
		PKCS8Key:   c.opts.Pkcs8Keys,
		ECSigAlg:   pkiutil.SupportedECSignatureAlgorithms(c.opts.ECCSigAlg),
		ECCCurve:   pkiutil.SupportedEllipticCurves(c.opts.ECCCurve),
	}

	// Generate the cert/key, send CSR to CA.
	csrPEM, keyPEM, err := pkiutil.GenCSR(options)
	if err != nil {
		log.Errorf("%s failed to generate key and certificate for CSR: %v", workloadCache.Name, err)
		return nil, err
	}
	certChainPEM, err := c.CSRSign(csrPEM, int64(c.opts.SecretTTL.Seconds()))
	if err != nil {
		return nil, err
	}
 
	certChain := concatCerts(certChainPEM)
	var expireTime time.Time
	// Cert expire time by default is createTime + sc.configOptions.SecretTTL.
	// Istiod respects SecretTTL that passed to it and use it decide TTL of cert it issued.
	// Some customer CA may override TTL param that's passed to it.
	if expireTime, err = nodeagentutil.ParseCertAndGetExpiryTimestamp(certChain); err != nil {
		log.Errorf("%s failed to extract expire time from server certificate in CSR response %+v: %v",
		workloadCache.Name, certChainPEM, err)
		return nil, fmt.Errorf("failed to extract expire time from server certificate in CSR response: %v", err)
	}

	rootCertPEM = []byte(certChainPEM[len(certChainPEM)-1])

	log.Infof("certChain is:%v", certChain);
	log.Infof("expireTime is:%v", expireTime);
	return &security.SecretItem{
		CertificateChain: certChain,
		PrivateKey:       keyPEM,
		ResourceName:     workloadCache.Name,
		CreatedTime:      time.Now(),
		ExpireTime:       expireTime,
		RootCert:         rootCertPEM,
	}, nil
 }
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

package security

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
	pb "istio.io/api/security/v1alpha1"
	"istio.io/istio/pkg/security"
	nodeagentutil "istio.io/istio/security/pkg/nodeagent/util"
	pkiutil "istio.io/istio/security/pkg/pki/util"
	"kmesh.net/kmesh/pkg/nets"
)
 
 var tlsOpts *TLSOptions 

 type KmeshCaClient struct {
	 tlsOpts  *TLSOptions
	 client   pb.IstioCertificateServiceClient
	 conn     *grpc.ClientConn
	 opts     *security.Options
 }

 type TLSOptions struct {
	RootCert string
	Key      string
	Cert     string
}
 
 // NewKmeshCaClient create a CA client for CSR sign.
 func NewKmeshCaClient(opts *security.Options, tlsOpts *TLSOptions) (*KmeshCaClient, error) {
	 var err error;
 
	 c := &KmeshCaClient{
		 tlsOpts:  tlsOpts,
		 opts:     opts,
	 }

	 conn, err := nets.GrpcConnect(CSRSignAddress);
	 if err != nil {
		 return nil, fmt.Errorf("failed to create grpcconnect : %v", err)
	 }
 
	 c.conn = conn
	 c.client = pb.NewIstioCertificateServiceClient(conn)
	 return c, nil
 }

// CSRSend send a grpc request to istio and sign a CSR.
func (c *KmeshCaClient) CSRSend(csrPEM []byte, certValidsec int64, csrHostName string) ([]string, error) {
	crMeta := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			security.ImpersonatedIdentity: {
				Kind: &structpb.Value_StringValue{StringValue: csrHostName},
			},
		},
	}
	req := &pb.IstioCertificateRequest{
		Csr:              string(csrPEM),
		ValidityDuration: certValidsec,
		Metadata:         crMeta,
	}

	ctx := context.Background()

	// To handle potential grpc connection disconnection and retry once 
	// when certificate acquisition fails. If it still fails, return an error.
	resp, err := c.client.CreateCertificate(ctx, req)
	if err != nil {
		log.Errorf("create certificate: %v reconnect...", err)
		if err := c.reconnect(); err != nil {
			return nil, fmt.Errorf("reconnect error: %v", err)
		}
		resp, err = c.client.CreateCertificate(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("create certificate: %v", err)
		}
	}

	if len(resp.CertChain) <= 1 {
		return nil, errors.New("invalid empty CertChain")
	}

	return resp.CertChain, nil
}

// Standard the PEM certificates, ensuring that each certificate starts on a new line
func standardCerts(certsPEM []string) []byte {
	var certChain strings.Builder
	for i, c := range certsPEM {
		certChain.WriteString(c)
		if i < len(certsPEM)-1 && !strings.HasSuffix(c, "\n") {
			certChain.WriteString("\n")
		}
	}
	return []byte(certChain.String())
}

func (c *KmeshCaClient) fetchCert(csrHostName string) (*security.SecretItem, error) {
	var rootCertPEM []byte
	
	options := pkiutil.CertOptions{
		Host:       csrHostName,
		RSAKeySize: c.opts.WorkloadRSAKeySize,
		PKCS8Key:   c.opts.Pkcs8Keys,
		ECSigAlg:   pkiutil.SupportedECSignatureAlgorithms(c.opts.ECCSigAlg),
		ECCCurve:   pkiutil.SupportedEllipticCurves(c.opts.ECCCurve),
	}

	// Generate the cert/key, send CSR to CA.
	csrPEM, keyPEM, err := pkiutil.GenCSR(options)
	if err != nil {
		log.Errorf("%s failed to generate key and certificate for CSR: %v", csrHostName, err)
		return nil, err
	}
	certChainPEM, err := c.CSRSend(csrPEM, int64(c.opts.SecretTTL.Seconds()), csrHostName)
	if err != nil {
		return nil, fmt.Errorf("failed to get certChainPEM")
	}

	certChain := standardCerts(certChainPEM)
	var expireTime time.Time
	
	if expireTime, err = nodeagentutil.ParseCertAndGetExpiryTimestamp(certChain); err != nil {
		return nil, fmt.Errorf("%s failed to extract expire time from server certificate in CSR response %+v: %v",
		csrHostName, certChainPEM, err)
	}

	rootCertPEM = []byte(certChainPEM[len(certChainPEM)-1])

	return &security.SecretItem{
		CertificateChain: certChain,
		PrivateKey:       keyPEM,
		ResourceName:     csrHostName,
		CreatedTime:      time.Now(),
		ExpireTime:       expireTime,
		RootCert:         rootCertPEM,
	}, nil
 }

 func (c *KmeshCaClient) reconnect() error {
	if err := c.conn.Close(); err != nil {
		return fmt.Errorf("failed to close connection: %v", err)
	}

	conn, err := nets.GrpcConnect(CSRSignAddress);
	if err != nil {
		return err
	}
	c.conn = conn
	c.client = pb.NewIstioCertificateServiceClient(conn)
	return nil
}

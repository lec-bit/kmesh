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
	"fmt"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"
	"istio.io/istio/pkg/security"
	camock "kmesh.net/kmesh/pkg/controller/security/mock"
)



func TestFileSecrets(t *testing.T) {
	t.Run("TestBaseCert", func(t *testing.T) {
		runTestBaseCert(t)
	})
	t.Run("TestCertRotate", func(t *testing.T) {
		runTestCertRotate(t)
	})
	t.Run("TestretryFetchCert", func(t *testing.T) {
		runTestretryFetchCert(t)
	})

}

// Test certificate add/delete
func runTestBaseCert(t *testing.T) {
	patches := gomonkey.NewPatches()
	patches.ApplyFunc(newCaClient, func(opts *security.Options, tlsOpts *tlsOptions) (CaClient, error) {
		return camock.NewMockCaClient(opts, 2*time.Hour)
	})
	defer patches.Reset()

	stopCh := make(chan struct{})
	secretManager, err := NewSecretManager()
	assert.ErrorIsf(t, err, nil, "NewSecretManager failed %v", err)
	go secretManager.Run(stopCh)

	identity1 := "identity1"
	identity2 := "identity2"

	secretManager.SendCertRequest(identity1, ADD)
	secretManager.SendCertRequest(identity1, ADD)
	secretManager.SendCertRequest(identity2, ADD)
	time.Sleep(1000 * time.Millisecond)
	log.Printf(">>>>>>>>>>>>%v", secretManager.certsCache.certs[identity1])
	log.Printf(">>>>>>>>>>》》%v", secretManager.certsCache.certs[identity2])
	assert.Equal(t, int32(2), secretManager.certsCache.certs[identity1].refCnt)
	assert.Equal(t, int32(1), secretManager.certsCache.certs[identity2].refCnt)

	secretManager.SendCertRequest(identity1, DELETE)
	secretManager.SendCertRequest(identity2, DELETE)
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int32(1), secretManager.certsCache.certs[identity1].refCnt)
	assert.Nil(t, secretManager.certsCache.certs[identity2])

	secretManager.SendCertRequest(identity1, DELETE)
	time.Sleep(100 * time.Millisecond)
	assert.Nil(t, secretManager.certsCache.certs[identity1])
	close(stopCh)
}

// Test certificate auto-refresh queue
func runTestCertRotate(t *testing.T) {
	patches := gomonkey.NewPatches()
	patches.ApplyFunc(newCaClient, func(opts *security.Options, tlsOpts *tlsOptions) (CaClient, error) {
		// One-hour validity period, it will be Rotated after 2 second.
		return camock.NewMockCaClient(opts, 1*time.Hour + 2*time.Second)
	})
	defer patches.Reset()

	stopCh := make(chan struct{})
	secretManager, err := NewSecretManager()
	assert.ErrorIsf(t, err, nil, "NewSecretManager failed %v", err)
	go secretManager.Run(stopCh)

	identity1 := "identity1"
	identity2 := "identity2"

	secretManager.SendCertRequest(identity1, ADD)
	secretManager.SendCertRequest(identity2, ADD)
	time.Sleep(1 * time.Second)
	log.Printf(">>>>>>>>>>>>>>>%v", secretManager.certsCache.certs[identity1])
	assert.NotNil(t, secretManager.certsCache.certs[identity1].cert.CertificateChain)
	oldCert1 := secretManager.certsCache.certs[identity1].cert.CertificateChain
	oldCert2 := secretManager.certsCache.certs[identity2].cert.CertificateChain

	// rotate cert
	time.Sleep(2 * time.Second)
	newCert1 := secretManager.certsCache.certs[identity1].cert.CertificateChain
	newCert2 := secretManager.certsCache.certs[identity2].cert.CertificateChain

	// check if the cert rotated
	assert.NotEqual(t, oldCert1, newCert1)
	assert.NotEqual(t, oldCert2, newCert2)

	secretManager.SendCertRequest(identity1, DELETE)
	secretManager.SendCertRequest(identity2, DELETE)
	close(stopCh)
}

// Test certificate retryFetchCert
func runTestretryFetchCert(t *testing.T) {
	patches1 := gomonkey.NewPatches()
	patches1.ApplyFunc(newCaClient, func(opts *security.Options, tlsOpts *tlsOptions) (CaClient, error) {
		return camock.NewMockCaClient(opts, 2*time.Hour)
	})
	defer patches1.Reset()

	stopCh := make(chan struct{})
	secretManager, err := NewSecretManager()
	assert.ErrorIsf(t, err, nil, "NewSecretManager failed %v", err)

	patches2 := gomonkey.NewPatches()
	patches2.ApplyMethodFunc(secretManager.caClient, "FetchCert", func (identity string) (*security.SecretItem, error) {
		return nil, fmt.Errorf("abnormal test")
	})

	go secretManager.Run(stopCh)
	identity := "identity"
	secretManager.SendCertRequest(identity, ADD)
	time.Sleep(100* time.Millisecond)
	patches2.Reset()
	time.Sleep(1100* time.Millisecond)
	assert.NotNil(t, secretManager.certsCache.certs[identity].cert)

	close(stopCh)
}


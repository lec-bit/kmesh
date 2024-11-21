//go:build integ || all
// +build integ all

/*
 * Copyright The Kmesh Authors.
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

package kmesh

import (
	"testing"
	"time"

	"istio.io/api/label"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/common/ports"
	"istio.io/istio/pkg/test/framework/components/echo/deployment"
	"istio.io/istio/pkg/test/framework/components/echo/match"
	"istio.io/istio/pkg/test/framework/components/namespace"
	"istio.io/istio/pkg/test/framework/resource"
)

var (
	apps = &EchoDeployments{}
)

type EchoDeployments struct {
	Namespace namespace.Instance
	All       echo.Instances

	// The echo service which is enrolled to Kmesh without waypoint.
	EnrolledToKmesh echo.Instances
}

const (
	ServiceName        = "echo-service"
	ServiceName2       = "echo-service2"
	EnrolledToKmesh    = "enrolled-to-kmesh"
	Timeout            = 2 * time.Minute
	KmeshReleaseName   = "kmesh"
	KmeshDaemonsetName = "kmesh"
	KmeshNamespace     = "kmesh-system"
	DataplaneModeKmesh = "Kmesh"
)

func TestMain(m *testing.M) {
	framework.
		NewSuite(m).
		Setup(func(t resource.Context) error {
			t.Settings().Ambient = true
			return nil
		}).
		Setup(func(t resource.Context) error {
			return SetupApps(t, apps)
		}).
		Run()
}

func SetupApps(t resource.Context, apps *EchoDeployments) error {
	var err error
	apps.Namespace, err = namespace.New(t, namespace.Config{
		Prefix: "echo",
		Inject: false,
		Labels: map[string]string{
			label.IoIstioDataplaneMode.Name: DataplaneModeKmesh,
		},
	})
	if err != nil {
		return err
	}

	builder := deployment.New(t).
		WithClusters(t.Clusters()...).
		WithConfig(echo.Config{
			Service:        ServiceName,
			Namespace:      apps.Namespace,
			Ports:          ports.All(),
			ServiceAccount: true,
			Subsets: []echo.SubsetConfig{
				{
					Replicas: 1,
					Version:  "v1",
					Labels: map[string]string{
						"app":     ServiceName,
						"version": "v1",
					},
				},
				{
					Replicas: 1,
					Version:  "v2",
					Labels: map[string]string{
						"app":     ServiceName,
						"version": "v2",
					},
				},
			},
		}).
		WithConfig(echo.Config{
			Service:        EnrolledToKmesh,
			Namespace:      apps.Namespace,
			Ports:          ports.All(),
			ServiceAccount: true,
			Subsets: []echo.SubsetConfig{
				{
					Replicas: 1,
					Version:  "v1",
				},
			},
		})

	echos, err := builder.Build()
	if err != nil {
		return err
	}

	apps.All = echos

	apps.EnrolledToKmesh = match.ServiceName(echo.NamespacedName{Name: EnrolledToKmesh, Namespace: apps.Namespace}).GetMatches(echos)
	return nil
}

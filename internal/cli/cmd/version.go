// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"github.com/cilium/cilium-cli/internal/k8s"
	"io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"runtime"
	"strings"

	"github.com/cilium/cilium-cli/defaults"

	"github.com/spf13/cobra"
)

// The following variables are set at compile time via LDFLAGS.
var (
	// Version is the software version.
	Version string
)

type CiliumVersion struct {
	client *k8s.Client
}

func NewCiliumVersion() *CiliumVersion {
	return &CiliumVersion{client: k8sClient}
}

func (c *CiliumVersion) GetRunningCiliumVersion(ctx context.Context) (string, error) {
	nss, err := c.client.ListNamespaces(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("unable to list k8s namespace: %w", err)
	}

	// First look for ns kube-system
	version, err := c.getCiliumVersionOfNamespace(ctx, "kube-system")
	if version != "" {
		return version, nil
	}

	if len(nss.Items) > 0 {
		for _, namespace := range nss.Items {
			version, err := c.getCiliumVersionOfNamespace(ctx, namespace.Name)
			if version != "" {
				return version, nil
			}
			if err != nil {
				return "", err
			}
		}
	}

	return "", errors.New("unable to obtain cilium version: no cilium pods found")
}

func (c *CiliumVersion) getCiliumVersionOfNamespace(ctx context.Context, namespace string) (string, error) {
	pods, err := c.client.ListPods(ctx, namespace, metav1.ListOptions{LabelSelector: "k8s-app=cilium"})
	if err != nil {
		return "", fmt.Errorf("unable to list cilium pods: %w", err)
	}
	if len(pods.Items) > 0 && len(pods.Items[0].Spec.Containers) > 0 {
		image := pods.Items[0].Spec.Containers[0].Image
		version := strings.SplitN(image, ":", 2)
		if len(version) != 2 {
			return "", errors.New("unable to extract cilium version from container image")
		}
		v := version[1]
		if digest := strings.Index(v, "@"); digest > 0 {
			v = v[:digest]
		}
		return v, nil
	}
	return "", nil
}

func getLatestStableVersion() string {
	resp, err := http.Get("https://raw.githubusercontent.com/cilium/cilium/master/stable.txt")
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "unknown"
	}

	return strings.TrimSpace(string(b))
}

func newCmdVersion() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Display detailed version information",
		Long:  `Displays information about the version of this software.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: add support for reporting the Cilium version running in
			// the cluster, if any. See https://github.com/cilium/cilium-cli/issues/131
			fmt.Printf("cilium-cli: %s compiled with %v on %v/%v\n", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
			fmt.Printf("cilium image (default): %s\n", defaults.Version)
			fmt.Printf("cilium image (stable): %s\n", getLatestStableVersion())
			ciliumVersion := NewCiliumVersion()
			version, err := ciliumVersion.GetRunningCiliumVersion(context.Background())
			if err != nil {
				fmt.Printf("cilium image (running): unknown,msg: %s %s\n", err.Error())
			} else {
				fmt.Printf("cilium image (running): %s\n", version)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")
	return cmd
}

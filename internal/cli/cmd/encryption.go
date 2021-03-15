// Copyright 2020 Authors of Cilium
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
	"os"
	"time"

	"github.com/cilium/cilium-cli/encryption"

	"github.com/spf13/cobra"
)

func newCmdEncryption() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "encryption",
		Short: "Encryption Management",
		Long:  ``,
	}

	cmd.AddCommand(
		newCmdEncryptionRotateKey(),
		newCmdEncryptionStatus(),
	)

	return cmd
}

func newCmdEncryptionStatus() *cobra.Command {
	var params = encryption.Parameters{
		Writer: os.Stdout,
	}

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show status of encryption",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			e := encryption.NewK8sEncryption(k8sClient, params)
			s, err := e.Status(context.Background(), true)
			if err != nil {
				fatalf("Unable to determine status:  %s", err)
			}
			s.Format(os.Stdout)
			return nil
		},
	}

	cmd.Flags().StringVar(&params.Namespace, "namespace", "kube-system", "Namespace Cilium is running in")
	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")
	cmd.Flags().BoolVar(&params.Wait, "wait", false, "Wait until status is successful")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", 15*time.Minute, "Maximum time to wait")

	return cmd
}

func newCmdEncryptionRotateKey() *cobra.Command {
	var params = encryption.Parameters{
		Writer: os.Stdout,
	}

	cmd := &cobra.Command{
		Use:   "rotate-key",
		Short: "Rotate the encryption key",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			e := encryption.NewK8sEncryption(k8sClient, params)
			if err := e.RotateKey(context.Background()); err != nil {
				fatalf("Unable to rotate key:  %s", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&params.Namespace, "namespace", "kube-system", "Namespace Cilium is running in")
	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")
	cmd.Flags().BoolVar(&params.Wait, "wait", false, "Wait until status is successful")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", 15*time.Minute, "Maximum time to wait")

	return cmd
}

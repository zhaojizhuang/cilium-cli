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

package encryption

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium-cli/defaults"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type k8sEncryptionImplementation interface {
	//	CreateSecret(ctx context.Context, namespace string, secret *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error)
	PatchSecret(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*corev1.Secret, error)
	//	DeleteSecret(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	GetSecret(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Secret, error)
	//	CreateServiceAccount(ctx context.Context, namespace string, account *corev1.ServiceAccount, opts metav1.CreateOptions) (*corev1.ServiceAccount, error)
	//	DeleteServiceAccount(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	//	CreateClusterRole(ctx context.Context, role *rbacv1.ClusterRole, opts metav1.CreateOptions) (*rbacv1.ClusterRole, error)
	//	DeleteClusterRole(ctx context.Context, name string, opts metav1.DeleteOptions) error
	//	CreateClusterRoleBinding(ctx context.Context, role *rbacv1.ClusterRoleBinding, opts metav1.CreateOptions) (*rbacv1.ClusterRoleBinding, error)
	//	DeleteClusterRoleBinding(ctx context.Context, name string, opts metav1.DeleteOptions) error
	//	GetConfigMap(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error)
	//	CreateDeployment(ctx context.Context, namespace string, deployment *appsv1.Deployment, opts metav1.CreateOptions) (*appsv1.Deployment, error)
	//	GetDeployment(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.Deployment, error)
	//	DeleteDeployment(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	//	CreateService(ctx context.Context, namespace string, service *corev1.Service, opts metav1.CreateOptions) (*corev1.Service, error)
	//	DeleteService(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	//	GetService(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Service, error)
	//	PatchDaemonSet(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*appsv1.DaemonSet, error)
	//	GetDaemonSet(ctx context.Context, namespace, name string, options metav1.GetOptions) (*appsv1.DaemonSet, error)
	//	ListNodes(ctx context.Context, options metav1.ListOptions) (*corev1.NodeList, error)
	//	ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error)
	//	AutodetectFlavor(ctx context.Context) (k8s.Flavor, error)
	//	CiliumStatus(ctx context.Context, namespace, pod string) (*models.StatusResponse, error)
	//	ClusterName() string
}

type K8sEncryption struct {
	client k8sEncryptionImplementation
	params Parameters
}

type Parameters struct {
	Namespace    string
	Wait         bool
	WaitDuration time.Duration
	Writer       io.Writer
}

func (p Parameters) waitTimeout() time.Duration {
	if p.WaitDuration != time.Duration(0) {
		return p.WaitDuration
	}

	return time.Minute * 15
}

func NewK8sEncryption(client k8sEncryptionImplementation, p Parameters) *K8sEncryption {
	return &K8sEncryption{
		client: client,
		params: p,
	}
}

func (k *K8sEncryption) Log(format string, a ...interface{}) {
	fmt.Fprintf(k.params.Writer, format+"\n", a...)
}

type Status struct {
	SecretAvailable bool
	Errors          []error
	KeyID           int
	Cipher          string
	KeyLength       int
}

func (k *K8sEncryption) getSecret(ctx context.Context, s *Status) {
	ipsecSecret, err := k.client.GetSecret(ctx, k.params.Namespace, defaults.EncryptionSecretName, metav1.GetOptions{})
	if err != nil {
		s.Errors = append(s.Errors, fmt.Errorf("unable to get secret %q to retrieve CA: %s", defaults.CASecretName, err))
	}

	s.SecretAvailable = true

	keys, ok := ipsecSecret.Data["keys"]
	if !ok {
		s.Errors = append(s.Errors, fmt.Errorf("secret %q does not contain keys", defaults.EncryptionSecretName))
	}

	tok := strings.Split(string(keys), " ")
	if len(tok) != 4 {
		s.Errors = append(s.Errors, fmt.Errorf("invalid IPSec key %q in secret %q, should be \"<id> <cipher> <key> <len>\"", string(keys), defaults.EncryptionSecretName))
	}

	n, err := strconv.Atoi(tok[0])
	if err != nil {
		s.Errors = append(s.Errors, fmt.Errorf("key ID %q is not a number: %s", tok[0], err))
	}
	s.KeyID = n
	s.Cipher = tok[1]

	n, err = strconv.Atoi(tok[3])
	if err != nil {
		s.Errors = append(s.Errors, fmt.Errorf("key length %q is not a number: %s", tok[3], err))
	}
	s.KeyLength = n
}

func (k *K8sEncryption) status(ctx context.Context) (*Status, error) {
	var s = &Status{}

	k.getSecret(ctx, s)

	return s, nil
}

func generateRandomKey(id int, cipher string) (string, error) {
	random := make([]byte, 20)
	_, err := rand.Read(random)
	if err != nil {
		return "", fmt.Errorf("unable to generate random sequence for key: %w", err)
	}

	key := fmt.Sprintf("%d %s ", id, cipher)
	for _, c := range random {
		key += fmt.Sprintf("%02x", c)
	}
	key += " 128"

	return key, nil
}

func (k *K8sEncryption) RotateKey(ctx context.Context) error {
	var s = &Status{}

	k.getSecret(ctx, s)
	if len(s.Errors) > 0 {
		return fmt.Errorf("unable to retrieve existing secret: %+v", s.Errors)
	}

	if s.KeyID == 3 {
		s.KeyID = 1
	} else {
		s.KeyID++
	}

	d, err := generateRandomKey(s.KeyID, s.Cipher)
	if err != nil {
		return fmt.Errorf("unable to generate new key: %s", err)
	}

	encodedKey := `"keys": "` + base64.StdEncoding.EncodeToString([]byte(d)) + `"`
	patch := []byte(`{"data":{` + encodedKey + `}}`)
	_, err = k.client.PatchSecret(ctx, k.params.Namespace, defaults.EncryptionSecretName, types.StrategicMergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("unable to patch secret %s with patch %q: %w", defaults.ClusterMeshSecretName, patch, err)
	}

	return nil
}

func (k *K8sEncryption) Status(ctx context.Context, log bool) (*Status, error) {
	return k.status(ctx)
}

func (s *Status) Format(w io.Writer) {
	if s.SecretAvailable {
		fmt.Fprintf(w, "✅ IPSec secret %q exists\n", defaults.EncryptionSecretName)
		fmt.Fprintf(w, "   - Key ID: %d\n", s.KeyID)
		fmt.Fprintf(w, "   - Cipher: %s\n", s.Cipher)
		fmt.Fprintf(w, "   - Key length: %d\n", s.KeyLength)
	}

	if len(s.Errors) > 0 {
		fmt.Fprintf(w, "Errors:\n")
		for _, err := range s.Errors {
			fmt.Fprintf(w, " - ❌ %s\n", err)
		}
	}
}

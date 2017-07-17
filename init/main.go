/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Note: the example only works with the code within the same release/branch.
package main

import (
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/apis/certificates/v1beta1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/cert"
	// Uncomment the following line to load the gcp plugin (only required to authenticate against GKE clusters).
	// _ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

func main() {
	var kubeconfig *string
	if home := homeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	key, err := cert.NewPrivateKey()
	if err != nil {
		log.Fatalf("could not generate cert, %v", err)
	}

	username := os.Getenv("KUBERNETES_POD_NAME")
	ipStr := os.Getenv("KUBERNETES_POD_IP")
	ip := net.ParseIP(ipStr)

	csr, err := cert.MakeCSR(key, &pkix.Name{CommonName: username}, []string{}, []net.IP{ip})
	if err != nil {
		log.Fatalf("could not generate cert, %v", err)
	}

	csrName := fmt.Sprintf("init-csr-%s", username)

	_, err = clientset.Certificates().CertificateSigningRequests().Create(&v1beta1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: csrName,
		},
		Spec: v1beta1.CertificateSigningRequestSpec{
			Request:  csr,
			Username: username,
			Usages: []v1beta1.KeyUsage{
				v1beta1.UsageDataEncipherment,
				v1beta1.UsageServerAuth,
			},
		},
	})
	if err != nil {
		return
	}

	defer clientset.Certificates().CertificateSigningRequests().Delete(csrName, &metav1.DeleteOptions{})

	var certdata []byte

	// should do a watch here
	for {
		csr, err := clientset.Certificates().CertificateSigningRequests().Get(csrName, metav1.GetOptions{})
		if err != nil {
			return
		}

		if len(csr.Status.Conditions) == 0 {
			time.Sleep(time.Second)
			continue
		}
		if len(csr.Status.Certificate) != 0 {
			certdata = csr.Status.Certificate
			break
		}

	}

	if err = cert.WriteCert("tls.crt", certdata); err != nil {
		return
	}

	if err = cert.WriteKey("tls.key", key.Public(); err != nil {
		return
	}
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}

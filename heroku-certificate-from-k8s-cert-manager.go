package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	heroku "github.com/heroku/heroku-go/v5"
)

var (
	secretName    = flag.String("secretName", "", "kubernetes secret")
	namespace = flag.String("namespace", "", "kubernetes namespace")

	herokuApp       = flag.String("herokuApp", "", "Heroku application name")
	herokuToken = flag.String("herokuToken", "", "Heroku application name")
)

type k8sCertificate struct {
	CertificateChain string
	PrivateKey       string
}

func main() {
	fmt.Println("start Heroku certificate from k8s cert-manager")

	err := initVariables()
	if err != nil {
		fmt.Printf("error getting args: %v\n", err)
		os.Exit(1)
	}

	k8sCertificate, err := getKubernetesCertificates()
	if err != nil {
		fmt.Printf("error getting kubernetes certificates: %v\n", err)
		os.Exit(1)
	}

	kubernetesTlsExpiresOn, err := getCertificateExpirationDate(k8sCertificate.CertificateChain)
	if err != nil {
		fmt.Printf("error getting kubernetes tls expires on: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("kubernetes TLS expiresOn %v\n", kubernetesTlsExpiresOn)
	kubernetesTlsCommonName, err := getCertificateCommonName(k8sCertificate.CertificateChain)
	if err != nil {
		fmt.Printf("error getting kubernetes tls common nam: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("kubernetes TLS common name %v\n", kubernetesTlsCommonName)

	sni, err := getHerokuSni(kubernetesTlsCommonName)
	if err != nil {
		fmt.Printf("error getting Heroku SNI: %v\n", err)
		os.Exit(1)
	}

	if (sni != nil) {
		herokuCertificateExpiresAt := sni.SSLCert.ExpiresAt
		fmt.Printf("Heroku TLS expires at %v\n", herokuCertificateExpiresAt)

		if (*kubernetesTlsExpiresOn != sni.SSLCert.ExpiresAt) {
			fmt.Println("both dates are not the same")
			uploadCertificateToHeroku(&k8sCertificate, sni.Name)
		} else {
			fmt.Println("both dates are identical. No need to update the heroku certificate.")
		}
	} else {
		fmt.Println("no SNI. Will install one")
		createCertificateToHeroku(&k8sCertificate)
	}
}

func initVariables() error {
	flag.Parse()
	if (*namespace == "") {
		*namespace = os.Getenv("namespace")
		if (*namespace == "") {
			return errors.New("namespace has no value")
		}
	}
	if (*secretName == "") {
		*secretName = os.Getenv("secretName")
		if (*secretName == "") {
			return errors.New("secretName has no value")
		}
	}
	if (*herokuApp == "") {
		*herokuApp = os.Getenv("herokuApp")
		if (*herokuApp == "") {
			return errors.New("herokuApp has no value")
		}
	}
	if (*herokuToken == "") {
		*herokuToken = os.Getenv("herokuToken")
		if (*herokuToken == "") {
			return errors.New("herokuToken has no value")
		}
	}
	
	return nil
}

func getClientset() (clientset *kubernetes.Clientset, err error) {
	// automountServiceAccountToken must not be set to false in kubernetes pod
	config, err := rest.InClusterConfig()
	if err != nil {
		fmt.Println("Using out-of-cluster mode")
		userHomeDir, err := os.UserHomeDir()
		if err != nil {
			fmt.Printf("error getting user home dir: %v\n", err)
			return nil, err
		}
		kubeConfigPath := filepath.Join(userHomeDir, ".kube", "config")
		fmt.Printf("Using kubeConfig: %s\n", kubeConfigPath)
		
		kubeConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
		if err != nil {
			fmt.Printf("Error getting kubernetes config: %v\n", err)
			return nil, err
		}
		clientset, err = kubernetes.NewForConfig(kubeConfig)
		if err != nil {
			fmt.Printf("error getting kubernetes client out cluster: %v\n", err)
			return nil, err
		}
		return clientset, err
	} else {	
		fmt.Println("Using in-of-cluster mode")
		clientset, err = kubernetes.NewForConfig(config)
		if err != nil {
			fmt.Printf("error getting kubernetes client inCluster: %v\n", err)
			return nil, err
		}
	}

	return clientset, err
}

func getKubernetesCertificates() (k8sCertificate k8sCertificate, err error) {
	clientset, err := getClientset()
	if err != nil {
		fmt.Printf("error getting kubernetes client: %v\n", err)
		return
	}

	secret, err := getSecret(*namespace, *secretName, clientset)
	if err != nil {
		fmt.Printf("error getting kubernetes secret: %v\n", err)
		return
	}
	fmt.Printf("secret name %v", secret.Name)

	fmt.Printf("secret type %v\n", secret.Type)
	k8sCertificate.CertificateChain = string(secret.Data["tls.crt"])
	k8sCertificate.PrivateKey = string(secret.Data["tls.key"])
	return
}

func getCertificateExpirationDate(crt string) (kubernetesTlsExpiresOn *time.Time, err error) {
	block, _ := pem.Decode([]byte(crt))
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("error parsing block certificate: %v\n", err)
		return
	}
	kubernetesTlsExpiresOn = &certificate.NotAfter
	return
}

func getCertificateCommonName(crt string) (kubernetesTlsCommonName string, err error) {
	block, _ := pem.Decode([]byte(crt))
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("error parsing block certificate: %v\n", err)
		return
	}
	kubernetesTlsCommonName = certificate.Subject.CommonName

	return
}

func getHerokuSni(commonName string) (herokuSniEndpoint *heroku.SniEndpoint, err error) {
	heroku.DefaultTransport.BearerToken = *herokuToken
	var app *heroku.App
	h := heroku.NewService(heroku.DefaultClient)
	app, err = h.AppInfo(context.TODO(), *herokuApp)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Heroku app name %v\n", app.Name)

	var sniResult heroku.SniEndpointListResult
	var lr *heroku.ListRange
	sniResult, err = h.SniEndpointList(context.TODO(), *herokuApp, lr)
	if err != nil {
		fmt.Println("Heroku : No sni endpoint list")
		fmt.Println(err)
		return
	}
	for _, sni := range sniResult {
		fmt.Printf("Heroku Sni Name: %v\n", sni.Name)
		sniCommonName, err := getCertificateCommonName(sni.CertificateChain)
		if err != nil {
			fmt.Printf("error getting sni tls common nam: %v\n", err)
			return nil, err
		}
		fmt.Printf("sni common name: %v\n", sniCommonName)
		if sniCommonName == commonName {
			herokuSniEndpoint = &sni
			return herokuSniEndpoint, nil
		}
	}
	return
}

func uploadCertificateToHeroku(certificate *k8sCertificate, sniEndpointIdentity string) (err error) {
	h := heroku.NewService(heroku.DefaultClient)

	var app *heroku.App
	app, err = h.AppInfo(context.TODO(), *herokuApp)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(app.Name)
	fmt.Println(app.CreatedAt)

	sniEndpointUpdateOpt := heroku.SniEndpointUpdateOpts{
		CertificateChain: certificate.CertificateChain,
		PrivateKey: certificate.PrivateKey,
	}
	sniEndpoint, err := h.SniEndpointUpdate(context.TODO(), *herokuApp, sniEndpointIdentity, sniEndpointUpdateOpt)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(sniEndpoint.Name)
	fmt.Println(sniEndpoint.Domains)
	fmt.Println(sniEndpoint.CreatedAt)
	fmt.Println(sniEndpoint.SSLCert.ExpiresAt)
	
	return
}

func createCertificateToHeroku(certificate *k8sCertificate) (err error) {
	h := heroku.NewService(heroku.DefaultClient)

	var app *heroku.App
	app, err = h.AppInfo(context.TODO(), *herokuApp)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(app.Name)
	fmt.Println(app.CreatedAt)

	fmt.Println("will create new SNI endpoint")

	sniEndpointCreateOpt := heroku.SniEndpointCreateOpts{
		CertificateChain: certificate.CertificateChain,
		PrivateKey: certificate.PrivateKey,
	}
	sniEndpoint, err := h.SniEndpointCreate(context.TODO(), *herokuApp, sniEndpointCreateOpt)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(sniEndpoint.Name)
	fmt.Println(sniEndpoint.Domains)
	fmt.Println(sniEndpoint.CreatedAt)
	fmt.Println(sniEndpoint.SSLCert.ExpiresAt)
	
	return
}

func getSecret(namespace string, secretName string, client *kubernetes.Clientset) (*v1.Secret, error) {
	fmt.Printf("Get Kubernetes secret %v:%v\n", namespace, secretName)
	secret, err := client.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		err = fmt.Errorf("error getting secret: %v", err)
		return nil, err
	}
	return secret, nil
}

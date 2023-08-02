package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"errors"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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
		fmt.Printf("error getting kubernetes certificates: %v\n", err)
		os.Exit(1)
	}

	k8sCertificate, err := getKubernetesCertificates()
	if err != nil {
		fmt.Printf("error getting kubernetes certificates: %v\n", err)
		os.Exit(1)
	}

	kubernetesTlsExpiresOn, err := getKubernetesCertificateExpirationDate(k8sCertificate.CertificateChain)
	if err != nil {
		fmt.Printf("error getting kubernetes tls expires on: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("kubernetes TLS expiresOn %v\n", kubernetesTlsExpiresOn)

	sni, err := getHerokuSni()
	if err != nil {
		fmt.Printf("error getting kubernetes tls expires on: %v\n", err)
		os.Exit(1)
	}

	if (sni != nil) {
		herokuCertificateExpiresAt := sni.SSLCert.ExpiresAt
		fmt.Printf("kubernetes TLS expires at %v\n", herokuCertificateExpiresAt)

		if (*kubernetesTlsExpiresOn != sni.SSLCert.ExpiresAt) {
			fmt.Println("both dates are not the same")
			uploadCertificateToHeroku(&k8sCertificate, sni.Name)
		}

		fmt.Println("both dates are identical. No need to update the heroku certificate.")
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

func getKubernetesCertificates() (k8sCertificate k8sCertificate, err error) {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("error getting user home dir: %v\n", err)
		return
	}
	os := runtime.GOOS
	var kubeConfigPath string
    switch os {
		case "windows":
		case "darwin":
			kubeConfigPath = filepath.Join(userHomeDir, ".kube", "config")
			fmt.Printf("Using kubeconfig: %s\n", kubeConfigPath)
		}

	kubeConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		fmt.Printf("Error getting kubernetes config: %v\n", err)
		return
	}

	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		fmt.Printf("error getting kubernetes config: %v\n", err)
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

func getKubernetesCertificateExpirationDate(crt string) (kubernetesTlsExpiresOn *time.Time, err error) {
	block, _ := pem.Decode([]byte(crt))
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("error parsing block certificate: %v\n", err)
		return
	}
	fmt.Printf("kubernetes certificate expires on: %v\n", certificate.NotAfter)
	kubernetesTlsExpiresOn = &certificate.NotAfter
	return
}

func getHerokuSni() (herokuSniEndpoint *heroku.SniEndpoint, err error) {
	heroku.DefaultTransport.BearerToken = *herokuToken
	var app *heroku.App
	h := heroku.NewService(heroku.DefaultClient)
	app, err = h.AppInfo(context.TODO(), *herokuApp)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(app.Name)
	fmt.Println(app.CreatedAt)

	var sniResult heroku.SniEndpointListResult
	var lr *heroku.ListRange
	sniResult, err = h.SniEndpointList(context.TODO(), *herokuApp, lr)
	if err != nil {
		fmt.Println("no sni endpoint list")
		fmt.Println(err)
		return
	}
	for _, sni := range sniResult {
		fmt.Println(sni.Name)
		fmt.Println(sni.Domains)
		fmt.Println(sni.CreatedAt)
		fmt.Println(sni.SSLCert.ExpiresAt)
		herokuSniEndpoint = &sni
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

package kubeconfig

import (
	"cert-tool/pkg/cert"
	"crypto"
	"crypto/x509"
	"os"

	"github.com/pkg/errors"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

func LoadKubeConfig(kubeconfigFile string) (*api.Config, error) {
	config, err := clientcmd.LoadFromFile(kubeconfigFile)
	if err != nil {
		return nil, errors.Wrapf(err, "load kubeconfig from file %s", kubeconfigFile)
	}
	return config, nil
}

func SaveKubeConfig(config *api.Config, kubeconfigFile string) error {
	if err := clientcmd.WriteToFile(*config, kubeconfigFile); err != nil {
		return errors.Wrapf(err, "write kubeconfig to file %s", kubeconfigFile)
	}
	return nil
}

func defaultName(name string) string {
	if name == "" {
		return "default"
	}
	return name
}

func defaultKubeConfig(clusterName, userName string) *api.Config {
	clusterName = defaultName(clusterName)
	userName = defaultName(userName)

	config := api.NewConfig()

	contextName := userName + "@" + clusterName
	config.Contexts[contextName] = &api.Context{
		Cluster:  clusterName,
		AuthInfo: userName,
	}
	config.CurrentContext = contextName
	return config
}

func GenerateKubeConfig(server, clusterName, userName string, caFile string, clientCert *x509.Certificate, clientKey crypto.Signer) (*api.Config, error) {
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, errors.Wrapf(err, `read ca file "%s"`, caFile)
	}

	certData := cert.CertToPEM(clientCert)
	keyData, err := cert.PrivateKeyToPEM(clientKey)
	if err != nil {
		return nil, errors.Wrap(err, "convert client key")
	}

	config := defaultKubeConfig(clusterName, userName)
	config.Clusters[defaultName(clusterName)] = &api.Cluster{
		Server:                   server,
		CertificateAuthorityData: ca,
	}

	config.AuthInfos[defaultName(userName)] = &api.AuthInfo{
		ClientCertificateData: certData,
		ClientKeyData:         keyData,
	}

	return config, nil
}

func GenerateKubeConfigWithFile(server, clusterName, userName string, caFile, clientCertFile, clientKeyFile string) (*api.Config, error) {
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, errors.Wrapf(err, `read ca file "%s"`, caFile)
	}

	if clusterName == "" {
		clusterName = "default"
	}
	if userName == "" {
		userName = "default"
	}

	config := defaultKubeConfig(clusterName, userName)
	config.Clusters[defaultName(clusterName)] = &api.Cluster{
		Server:                   server,
		CertificateAuthorityData: ca,
	}

	config.AuthInfos[defaultName(userName)] = &api.AuthInfo{
		ClientCertificate: clientCertFile,
		ClientKey:         clientKeyFile,
	}

	return config, nil
}

func IsKubeConfigFile(kubeconfigFile string) bool {
	_, err := clientcmd.LoadFromFile(kubeconfigFile)
	return err == nil
}

func LoadCert(kubeconfigFile string) (*x509.Certificate, error) {
	config, err := LoadKubeConfig(kubeconfigFile)
	if err != nil {
		return nil, err
	}
	if len(config.Contexts) == 0 {
		return nil, errors.Errorf("no contexts found in kubeconfig %s", kubeconfigFile)
	}
	context := config.Contexts[config.CurrentContext]
	if context == nil {
		return nil, errors.Errorf("current context %s not found in kubeconfig %s", config.CurrentContext, kubeconfigFile)
	}
	if len(config.AuthInfos) == 0 {
		return nil, errors.Errorf("no authInfos found in kubeconfig %s", kubeconfigFile)
	}
	authInfo := config.AuthInfos[context.AuthInfo]
	if authInfo == nil {
		return nil, errors.Errorf("authInfo %s not found in kubeconfig %s", config.Contexts[config.CurrentContext].AuthInfo, kubeconfigFile)
	}
	if authInfo.ClientCertificate != "" {
		return cert.LoadCert(authInfo.ClientCertificate)
	}
	if authInfo.ClientCertificateData != nil {
		return cert.LoadCertData(authInfo.ClientCertificateData)
	}

	return nil, errors.Errorf("no client certificate found in kubeconfig %s", kubeconfigFile)
}

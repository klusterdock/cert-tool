package cmds

import (
	"cert-tool/pkg/cert"
	"cert-tool/pkg/file"
	"cert-tool/pkg/kubeconfig"
	"crypto"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/thoas/go-funk"
)

func kubeConfigCmd() *cobra.Command {
	var (
		server         string
		clusterName    string
		userName       string
		commonName     string
		orgs           []string
		expiryDays     int
		timeToleration time.Duration
		caCertFile     string
		caKeyFile      string
		clientCertFile string
		clientKeyFile  string
		algo           string
		bits           int
	)

	cmd := &cobra.Command{
		Use:   "kubeconfig",
		Short: "Generate kubeconfig file for Kubernetes components",
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputFile == "" {
				return fmt.Errorf("output file is required")
			}
			if exist, err := file.IsFileExist(outputFile); err != nil {
				return err
			} else if exist && !force {
				return fmt.Errorf("output file %s already exists", outputFile)
			}

			if server == "" {
				return fmt.Errorf("server address is required")
			}
			if caCertFile == "" {
				return fmt.Errorf("ca file is required")
			}

			if clientCertFile != "" && clientKeyFile != "" {
				config, err := kubeconfig.GenerateKubeConfigWithFile(server, clusterName, userName, caCertFile, clientCertFile, clientKeyFile)
				if err != nil {
					return err
				}
				return kubeconfig.SaveKubeConfig(config, outputFile)
			}

			if clientCertFile != "" || clientKeyFile != "" {
				return fmt.Errorf("client certificate and key must be set together")
			}

			if caKeyFile == "" {
				return fmt.Errorf("ca key file is required")
			}

			if commonName == "" {
				return fmt.Errorf("common name is required")
			}

			if algo != "rsa" && algo != "ec" {
				return fmt.Errorf("unsupported algorithm %s", algo)
			}
			if bits < 0 {
				return fmt.Errorf("bits must be greater than 0")
			}
			if algo == "ec" && !funk.ContainsInt(cert.GetAllECBitSizes(), bits) {
				return fmt.Errorf("unsupported bits for ec %d", bits)
			}

			ca, err := cert.LoadCert(caCertFile)
			if err != nil {
				return err
			}
			caKey, err := cert.LoadPrivateKey(caKeyFile)
			if err != nil {
				return err
			}

			var key crypto.Signer
			switch algo {
			case "rsa":
				key, err = cert.GenerateRSAPrivateKey(bits)
				if err != nil {
					return err
				}
			case "ec":
				key, err = cert.GenerateECPrivateKey(bits)
				if err != nil {
					return err
				}
			}
			c, err := cert.SignCertificate(commonName, orgs, nil, false, true, expiryDays, timeToleration, key, ca, caKey)
			if err != nil {
				return err
			}
			config, err := kubeconfig.GenerateKubeConfig(server, clusterName, userName, caCertFile, c, key)
			if err != nil {
				return err
			}
			return kubeconfig.SaveKubeConfig(config, outputFile)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&server, "server", "", "the server address of the cluster")
	flags.StringVar(&clusterName, "cluster", "default", "the name of the cluster")
	flags.StringVar(&userName, "user", "default", "the name of the user")
	flags.StringVar(&commonName, "name", "", "the common name of the certificate")
	flags.StringArrayVar(&orgs, "orgs", nil, "the organizations of the certificate")
	flags.IntVar(&expiryDays, "days", 365, "certificate expiry days")
	flags.DurationVar(&timeToleration, "time-toleration", time.Minute*5, "the toleration for time diffrences between servers")
	flags.StringVar(&caCertFile, "ca-cert", "", "the file path of ca certificate")
	flags.StringVar(&caKeyFile, "ca-key", "", "the file path of ca private key")
	flags.StringVar(&clientCertFile, "cert", "", "the file path of client certificate key")
	flags.StringVar(&clientKeyFile, "key", "", "the file path of client private key")
	flags.StringVar(&algo, "algo", "rsa", "the algorithm of private key, options are rsa, ec")
	flags.IntVar(&bits, "bits", 2048, fmt.Sprintf("the bits of rsa or ec key, options for ec are %s", strings.Join(cert.GetAllECBitSizesString(), ", ")))
	return cmd
}

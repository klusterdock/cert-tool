package cmds

import (
	"cert-tool/pkg/cert"
	"cert-tool/pkg/file"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

func certCmd() *cobra.Command {
	var (
		commonName     string
		orgs           []string
		alterNames     []string
		expiryDays     int
		timeToleration time.Duration
		caCertFile     string
		caKeyFile      string
		keyFile        string
		forServer      bool
		forClient      bool
	)

	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Generate certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputFile == "" {
				return fmt.Errorf("output file is required")
			}
			if keyFile == "" {
				return fmt.Errorf("key file is required")
			}

			if outputFile != keyFile {
				if exist, err := file.IsFileExist(outputFile); err != nil {
					return err
				} else if exist && !force {
					return fmt.Errorf("output file %s already exists", outputFile)
				}
			}

			if commonName == "" {
				return fmt.Errorf("common name is required")
			}

			if caCertFile == "" {
				return fmt.Errorf("ca file is required")
			}
			if caKeyFile == "" {
				return fmt.Errorf("ca key file is required")
			}

			if expiryDays < 0 {
				return fmt.Errorf("expiry days must be greater than 0")
			}
			if timeToleration < 0 {
				return fmt.Errorf("time toleration must be greater than 0")
			}
			ca, err := cert.LoadCert(caCertFile)
			if err != nil {
				return err
			}
			caKey, err := cert.LoadPrivateKey(caKeyFile)
			if err != nil {
				return err
			}
			key, err := cert.LoadPrivateKey(keyFile)
			if err != nil {
				return err
			}

			c, err := cert.SignCertificate(commonName, orgs, alterNames, forServer, forClient, expiryDays, timeToleration, key, ca, caKey)
			if err != nil {
				return err
			}
			return cert.SaveCert(c, outputFile, outputFile == keyFile)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&commonName, "name", "", "the common name of the certificate")
	flags.StringArrayVar(&orgs, "orgs", nil, "the organizations of the certificate")
	flags.StringArrayVar(&alterNames, "names", nil, "the alternative names of the certificate")
	flags.IntVar(&expiryDays, "days", 365, "certificate expiry days")
	flags.DurationVar(&timeToleration, "time-toleration", time.Minute*5, "the toleration for time diffrences between servers")
	flags.StringVar(&caCertFile, "ca-cert", "", "the file path of ca certificate")
	flags.StringVar(&caKeyFile, "ca-key", "", "the file path of ca private key")
	flags.StringVar(&keyFile, "key", "", "the file path of private key")
	flags.BoolVar(&forServer, "server", false, "the certificate is for server")
	flags.BoolVar(&forClient, "client", false, "the certificate is for client")
	return cmd
}

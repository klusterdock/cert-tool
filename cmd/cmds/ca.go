package cmds

import (
	"cert-tool/pkg/cert"
	"cert-tool/pkg/file"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

func caCmd() *cobra.Command {
	var (
		commonName     string
		expiryDays     int
		timeToleration time.Duration
		keyFile        string
	)

	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Generate CA certificate",
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
			if expiryDays < 0 {
				return fmt.Errorf("expiry days must be greater than 0")
			}
			if timeToleration < 0 {
				return fmt.Errorf("time toleration must be greater than 0")
			}

			key, err := cert.LoadPrivateKey(keyFile)
			if err != nil {
				return err
			}

			c, err := cert.GenerateCA(commonName, expiryDays, timeToleration, key)
			if err != nil {
				return err
			}
			return cert.SaveCert(c, outputFile, outputFile == keyFile)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&commonName, "name", "", "the common name of the certificate")
	flags.IntVar(&expiryDays, "days", 365*10, "certificate expiry days")
	flags.DurationVar(&timeToleration, "time-toleration", time.Minute*5, "the toleration for time diffrences between servers")
	flags.StringVar(&keyFile, "key", "", "the file path of private key")
	return cmd
}

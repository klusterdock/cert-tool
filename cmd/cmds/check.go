package cmds

import (
	"cert-tool/pkg/cert"
	"cert-tool/pkg/kubeconfig"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

func checkExpiryCmd() *cobra.Command {
	var daysBefore int

	cmd := &cobra.Command{
		Use:   "check-expiry [INPUT_FILES...]",
		Short: "Check the certificate if it is expired",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("at least one input file is required")
			}
			if daysBefore < 0 {
				return fmt.Errorf("days before must be greater than 0")
			}

			now := time.Now()
			hasInvalid := false
			for _, input := range args {
				var c *x509.Certificate
				var err error
				if kubeconfig.IsKubeConfigFile(input) {
					c, err = kubeconfig.LoadCert(input)
				} else {
					c, err = cert.LoadCert(input)
				}
				if err != nil {
					return fmt.Errorf("failed to load certificate from %s", input)
				}
				if now.After(c.NotAfter) {
					hasInvalid = true
					fmt.Printf("%s expired at %s\n", input, c.NotAfter)
				}

				if daysBefore != 0 && now.Add(time.Hour*24*time.Duration(daysBefore)).After(c.NotAfter) {
					hasInvalid = true
					fmt.Printf("%s will be expired on %s\n", input, c.NotAfter)
				}

				if now.Before(c.NotBefore) {
					hasInvalid = true
					fmt.Printf("%s will be effective on %s\n", input, c.NotBefore)
				}

				fmt.Printf("%s is valid\n", input)
			}
			if hasInvalid {
				return fmt.Errorf("some certificates are invalid")
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&daysBefore, "days-before", 0, "check if the certificate will be expired in the days")

	return cmd
}

package cmds

import (
	"cert-tool/pkg/cert"
	"cert-tool/pkg/file"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thoas/go-funk"
)

func keyCmd() *cobra.Command {
	var (
		algo string
		bits int
	)

	cmd := &cobra.Command{
		Use:   "key",
		Short: "Generate private key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputFile == "" {
				return fmt.Errorf("output file is required")
			}
			if exist, err := file.IsFileExist(outputFile); err != nil {
				return err
			} else if exist && !force {
				return fmt.Errorf("output file %s already exists", outputFile)
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

			switch algo {
			case "rsa":
				key, err := cert.GenerateRSAPrivateKey(bits)
				if err != nil {
					return err
				}
				return cert.SaveRSAPrivateKey(key, outputFile)
			case "ec":
				key, err := cert.GenerateECPrivateKey(bits)
				if err != nil {
					return err
				}
				return cert.SaveECPrivateKey(key, outputFile)
			}
			return nil
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&algo, "algo", "rsa", "the algorithm of private key, options are rsa, ec")
	flags.IntVar(&bits, "bits", 2048, fmt.Sprintf("the bits of rsa or ec key, options for ec are %s", strings.Join(cert.GetAllECBitSizesString(), ", ")))
	return cmd
}

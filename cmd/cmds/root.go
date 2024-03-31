package cmds

import (
	"cert-tool/version"

	"github.com/spf13/cobra"
)

var (
	outputFile string
	force      bool
)

func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:              "cert-tool",
		Long:             "cert-tool is a tool to generate certificates for Kubernetes components.",
		SilenceUsage:     true,
		SilenceErrors:    false,
		TraverseChildren: true,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
		Version: version.BuildVersion,
	}
	flags := root.PersistentFlags()
	flags.StringVarP(&outputFile, "output", "o", "", "the file path to store the output")
	flags.BoolVarP(&force, "force", "f", false, "force to overwrite the existing file")

	root.AddCommand(keyCmd(), caCmd(), certCmd(), kubeConfigCmd(), checkExpiryCmd())
	return root
}

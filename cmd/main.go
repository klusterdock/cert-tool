package main

import (
	option "cert-tool/cmd/cmds"
	"log"
	"os"

	"github.com/spf13/pflag"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	flags := pflag.NewFlagSet("cert-tool", pflag.ExitOnError)
	pflag.CommandLine = flags

	root := option.NewRootCommand()
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

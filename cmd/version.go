package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version  = "1.0.5"
	codename = "XrayR"
	intro    = "A Xray backend that supports many panels"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print current version of XrayR",
		Run: func(_ *cobra.Command, _ []string) {
			showVersion()
		},
	})
}

func showVersion() {
	fmt.Printf("%s %s (%s) \n", codename, version, intro)
}

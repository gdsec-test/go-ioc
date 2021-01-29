package cmd

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/gdcorp-infosec/go-ioc/ioc"
	"github.com/spf13/cobra"
)

var stdinCommand = &cobra.Command{
	Use:   "stdin",
	Short: "Find IOCs from stdin",

	Run: func(cmd *cobra.Command, args []string) {
		stdin, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			fmt.Println(err)
		}
		iocs := ioc.GetIOCs(string(stdin), getFangedIOCs, standardizeDefangs)
		printIOCHelper(iocs)
	},
}

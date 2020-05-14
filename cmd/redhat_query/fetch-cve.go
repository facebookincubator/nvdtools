package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/facebookincubator/nvdtools/providers/lib/client"
	"github.com/facebookincubator/nvdtools/providers/redhat/api"
)

var fetchCVECmd = &cobra.Command{
	Use:   "fetch-cve CVE-XXXX-YYYY",
	Short: "fetch the latest information about a CVE",
	RunE:  fetchCVE,
}

func init() {
	rootCmd.AddCommand(fetchCVECmd)
}

func fetchCVE(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return errors.New("fetch-cve: missing CVE name")
	}
	cveID := args[0]

	httpClient := client.Default()
	config := client.Config{
		UserAgent: "redhat_query",
	}
	httpClient = config.Configure(httpClient)

	feed := api.NewClient(httpClient, "https://access.redhat.com/labs/securitydataapi")
	cve, err := feed.FetchCVE(context.Background(), cveID)
	if err != nil {
		return err
	}

	output, err := json.MarshalIndent(cve, "", " ")
	if err != nil {
		return err
	}

	fmt.Println(string(output))

	return nil
}

package cmd

import (
	"fmt"
	"os"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/pkg/edgegrid"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type EdgegridOption struct {
	edgegridFile    string
	edgegridSection string
	accountKey      string
	host            string
	clientToken     string
	clientSecret    string
	accessToken     string
}

func (eg *EdgegridOption) Signer() (*edgegrid.Config, error) {
	egpath, err := homedir.Expand(eg.edgegridFile)
	if err != nil {
		return nil, fmt.Errorf("failed to expand home directory path: %w", err)
	}

	var edgerc *edgegrid.Config
	if _, err = os.Stat(egpath); err == nil {
		if edgerc, err = edgegrid.New(
			edgegrid.WithFile(egpath),
			edgegrid.WithSection(eg.edgegridSection),
		); err != nil {
			return nil, err
		}
	} else {
		edgerc, _ = edgegrid.New()

		if eg.host != "" {
			edgerc.Host = eg.host
		}
		if eg.clientToken != "" {
			edgerc.ClientToken = eg.clientToken
		}
		if eg.clientSecret != "" {
			edgerc.ClientSecret = eg.clientSecret
		}
		if eg.accessToken != "" {
			edgerc.AccessToken = eg.accessToken
		}
	}

	if edgerc.Host == "" || edgerc.ClientToken == "" || edgerc.ClientSecret == "" || edgerc.AccessToken == "" {
		return nil, fmt.Errorf("missing required Edgegrid configuration")
	}

	if eg.accountKey != "" {
		edgerc.AccountKey = eg.accountKey
	}

	return edgerc, nil
}

var egOption *EdgegridOption

func Execute() {
	fs := pflag.NewFlagSet("edgegrid", pflag.ContinueOnError)
	fs.StringVarP(&egOption.edgegridFile, "file", "r", "~/.edgerc", "Path to the .edgerc file.")
	fs.StringVarP(&egOption.edgegridSection, "section", "s", "default", "The section of the .edgerc file to use.")
	fs.StringVarP(&egOption.accountKey, "key", "k", "", "Account switch key for authorization.")
	fs.StringVar(&egOption.host, "host", "", "The API host.")
	fs.StringVar(&egOption.clientToken, "client-token", "", "The client token for authentication.")
	fs.StringVar(&egOption.clientSecret, "client-secret", "", "The client secret for authentication.")
	fs.StringVar(&egOption.accessToken, "access-token", "", "The access token for authentication.")

	fs.SetInterspersed(false)
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	rootCmd := &cobra.Command{
		Use:   "edgegrid",
		Short: "A command-line tool for Akamai's Edgegrid API",
		Long:  `A longer description that spans multiple lines and likely contains examples and usage of using your application.`,
	}

	rootCmd.AddCommand(curlCmd)
	rootCmd.AddCommand(proxyCmd)
	rootCmd.SetArgs(fs.Args())
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	egOption = new(EdgegridOption)
}

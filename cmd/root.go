package cmd

import (
	"fmt"
	"os"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/pkg/edgegrid"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
)

var (
	edgegridFile    string
	edgegridSection string
	accountKey      string
	host            string
	clientToken     string
	clientSecret    string
	accessToken     string
)

var rootCmd = &cobra.Command{
	Use:   "edgegrid",
	Short: "A command-line tool for Akamai's Edgegrid API",
	Long:  `A longer description that spans multiple lines and likely contains examples and usage of using your application.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&edgegridFile, "file", "r", "~/.edgerc", "Path to the .edgerc file.")
	rootCmd.PersistentFlags().StringVarP(&edgegridSection, "section", "s", "default", "The section of the .edgerc file to use.")
	rootCmd.PersistentFlags().StringVarP(&accountKey, "key", "k", "", "Account switch key for authorization.")
	rootCmd.PersistentFlags().StringVar(&host, "host", "", "The API host.")
	rootCmd.PersistentFlags().StringVar(&clientToken, "client-token", "", "The client token for authentication.")
	rootCmd.PersistentFlags().StringVar(&clientSecret, "client-secret", "", "The client secret for authentication.")
	rootCmd.PersistentFlags().StringVar(&accessToken, "access-token", "", "The access token for authentication.")
}

func edgerc() (*edgegrid.Config, error) {
	egpath, err := homedir.Expand(edgegridFile)
	if err != nil {
		return nil, fmt.Errorf("failed to expand home directory path: %w", err)
	}

	var edgerc *edgegrid.Config
	if _, err = os.Stat(egpath); err == nil {
		if edgerc, err = edgegrid.New(
			edgegrid.WithFile(egpath),
			edgegrid.WithSection(edgegridSection),
		); err != nil {
			return nil, err
		}
	} else {
		edgerc, _ = edgegrid.New()

		if host != "" {
			edgerc.Host = host
		}
		if clientToken != "" {
			edgerc.ClientToken = clientToken
		}
		if clientSecret != "" {
			edgerc.ClientSecret = clientSecret
		}
		if accessToken != "" {
			edgerc.AccessToken = accessToken
		}
	}

	if edgerc.Host == "" || edgerc.ClientToken == "" || edgerc.ClientSecret == "" || edgerc.AccessToken == "" {
		return nil, fmt.Errorf("missing required Edgegrid configuration")
	}

	if accountKey != "" {
		edgerc.AccountKey = accountKey
	}

	return edgerc, nil
}

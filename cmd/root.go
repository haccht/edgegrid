package cmd

import (
	"fmt"
	"os"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/pkg/edgegrid"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
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
	egpath, err := homedir.Expand(viper.GetString("file"))
	if err != nil {
		return nil, fmt.Errorf("failed to expand home directory path: %w", err)
	}

	var edgerc *edgegrid.Config
	if _, err = os.Stat(egpath); err == nil {
		if edgerc, err = edgegrid.New(
			edgegrid.WithFile(egpath),
			edgegrid.WithSection(viper.GetString("section")),
		); err != nil {
			return nil, err
		}
	} else {
		edgerc, _ = edgegrid.New()
	}

	if host := viper.GetString("host"); host != "" {
		edgerc.Host = host
	}
	if clientToken := viper.GetString("client-token"); clientToken != "" {
		edgerc.ClientToken = clientToken
	}
	if clientSecret := viper.GetString("client-secret"); clientSecret != "" {
		edgerc.ClientSecret = clientSecret
	}
	if accessToken := viper.GetString("access-token"); accessToken != "" {
		edgerc.AccessToken = accessToken
	}
	if edgerc.Host == "" || edgerc.ClientToken == "" || edgerc.ClientSecret == "" || edgerc.AccessToken == "" {
		return nil, fmt.Errorf("missing required Edgegrid configuration")
	}

	if accountKey := viper.GetString("key"); accountKey != "" {
		edgerc.AccountKey = accountKey
	}

	return edgerc, nil
}

var egOption *EdgegridOption
var	rootCmd = &cobra.Command{
		Use:   "edgegrid",
		Short: "A command-line tool for Akamai's Edgegrid API",
		Long:  `A longer description that spans multiple lines and likely contains examples and usage of using your application.`,
	}

func Execute() {
	fs := pflag.NewFlagSet("edgegrid", pflag.ContinueOnError)
	fs.StringVarP(&egOption.edgegridFile, "file", "r", "~/.edgerc", "Path to the .edgerc file.")
	fs.StringVarP(&egOption.edgegridSection, "section", "s", "default", "The section of the .edgerc file to use.")
	fs.StringVarP(&egOption.accountKey, "key", "k", "", "Account switch key for authorization.")
	fs.StringVar(&egOption.host, "host", "", "The API host.")
	fs.StringVar(&egOption.clientToken, "client-token", "", "The client token for authentication.")
	fs.StringVar(&egOption.clientSecret, "client-secret", "", "The client secret for authentication.")
	fs.StringVar(&egOption.accessToken, "access-token", "", "The access token for authentication.")

	viper.BindPFlags(fs)
	viper.BindEnv("key", "EDGEGRID_ACCOUNT_KEY")
	viper.BindEnv("host", "EDGEGRID_HOST")
	viper.BindEnv("client-token", "EDGEGRID_CLIENT_TOKEN")
	viper.BindEnv("client-secret", "EDGEGRID_CLIENT_SECRET")
	viper.BindEnv("access-token", "EDGEGRID_ACCESS_TOKEN")

	fs.SetInterspersed(false)
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
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

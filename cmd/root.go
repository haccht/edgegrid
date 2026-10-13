package cmd

import (
	"errors"
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
var rootCmd = &cobra.Command{
	Use:   "edgegrid",
	Short: "A command-line tool for Akamai's Edgegrid API",
	Long: `edgegrid is a command-line tool for signing requests to the Akamai API
with the EdgeGrid authentication scheme.

It provides two subcommands:
  curl   Signs and sends a single HTTP request to the Akamai API.
  proxy  Starts a reverse proxy that signs incoming requests and forwards them to the Akamai API.`,
}

func Execute() {
	fs := rootCmd.Flags()
	fs.Usage = func() {}
	fs.SetInterspersed(false)

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			_ = rootCmd.Help()
			return
		}
		fmt.Println(err)
		os.Exit(2)
	}

	rootCmd.SetArgs(fs.Args())
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	egOption = new(EdgegridOption)
	rootCmd.AddCommand(curlCmd)
	rootCmd.AddCommand(proxyCmd)
	rootCmd.InitDefaultHelpFlag()

	rootCmd.Flags().StringVarP(&egOption.edgegridFile, "file", "r", "~/.edgerc", "Path to the .edgerc file.")
	rootCmd.Flags().StringVarP(&egOption.edgegridSection, "section", "s", "default", "The section of the .edgerc file to use.")
	rootCmd.Flags().StringVarP(&egOption.accountKey, "key", "k", "", "Account switch key for authorization. (env: EDGEGRID_ACCOUNT_KEY)")
	rootCmd.Flags().StringVar(&egOption.host, "host", "", "The API host. (env: EDGEGRID_HOST)")
	rootCmd.Flags().StringVar(&egOption.clientToken, "client-token", "", "The client token for authentication. (env: EDGEGRID_CLIENT_TOKEN)")
	rootCmd.Flags().StringVar(&egOption.clientSecret, "client-secret", "", "The client secret for authentication. (env: EDGEGRID_CLIENT_SECRET)")
	rootCmd.Flags().StringVar(&egOption.accessToken, "access-token", "", "The access token for authentication. (env: EDGEGRID_ACCESS_TOKEN)")

	viper.BindPFlags(rootCmd.Flags())
	viper.BindEnv("key", "EDGEGRID_ACCOUNT_KEY")
	viper.BindEnv("host", "EDGEGRID_HOST")
	viper.BindEnv("client-token", "EDGEGRID_CLIENT_TOKEN")
	viper.BindEnv("client-secret", "EDGEGRID_CLIENT_SECRET")
	viper.BindEnv("access-token", "EDGEGRID_ACCESS_TOKEN")
}

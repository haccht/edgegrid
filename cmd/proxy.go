package cmd

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/spf13/cobra"
)

var (
	proxyAddr    string
	proxyTLSCert string
	proxyTLSKey  string
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Starts a signing reverse proxy.",
	Long:  "This command starts a reverse proxy that automatically signs incoming requests and forwards them to the Akamai API.",
	RunE: func(cmd *cobra.Command, args []string) error {
		edSigner, err := egOption.Signer()
		if err != nil {
			return err
		}

		var proxyScheme string
		switch {
		case proxyTLSCert == "" && proxyTLSKey == "":
			proxyScheme = "http"
		case proxyTLSCert != "" && proxyTLSKey != "":
			proxyScheme = "https"
		default:
			return fmt.Errorf("both --tls-crt and --tls-key must be provided to enable HTTPS")
		}

		apiHost := &url.URL{Scheme: "https", Host: edSigner.Host}
		egproxy := httputil.NewSingleHostReverseProxy(apiHost)
		director := egproxy.Director

		egproxy.Director = func(req *http.Request) {
			req.Host = apiHost.Host
			director(req)
			edSigner.SignRequest(req)
			log.Printf("[proxy] request forwarded: %s %s", req.Method, req.URL.String())
		}

		egproxy.ModifyResponse = func(resp *http.Response) error {
			loc := resp.Header.Get("Location")
			if loc == "" {
				return nil
			}

			u, err := url.Parse(loc)
			if err != nil {
				log.Printf("[proxy] failed to parse Location header: %v", err)
				return nil
			}

			u.Scheme = proxyScheme
			u.Host = proxyAddr

			resp.Header.Set("Location", u.String())
			return nil
		}

		log.Printf("[proxy] ClientToken: %s", edSigner.ClientToken)
		if edSigner.AccountKey != "" {
			log.Printf("[proxy] AccountSwitchKey: %s", edSigner.AccountKey)
		}

		log.Printf("[proxy] starting server on: %s://%s", proxyScheme, proxyAddr)
		http.Handle("/", egproxy)

		if proxyScheme == "https" {
			return http.ListenAndServeTLS(proxyAddr, proxyTLSCert, proxyTLSKey, nil)
		}
		return http.ListenAndServe(proxyAddr, nil)
	},
}

func init() {
	proxyCmd.Flags().StringVarP(&proxyAddr, "addr", "a", "127.0.0.1:8080", "The address for the proxy server to listen on.")
	proxyCmd.Flags().StringVar(&proxyTLSCert, "tls-crt", "", "The path to the TLS certificate file for the proxy.")
	proxyCmd.Flags().StringVar(&proxyTLSKey, "tls-key", "", "The path to the TLS key file for the proxy.")
}

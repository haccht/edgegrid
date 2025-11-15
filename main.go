package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/pkg/edgegrid"
	"github.com/jessevdk/go-flags"
	"github.com/mitchellh/go-homedir"
)

// rootCmd contains the root command options that are shared across all subcommands.
type rootCmd struct {
	EdgegridFile    string `short:"r" long:"file" description:"Location of the Edgegrid configuration file" default:"~/.edgerc"`
	EdgegridSection string `short:"s" long:"section" description:"Section of the Edgegrid configuration file to use" default:"default"`
	AccountKey      string `short:"k" long:"key" env:"EDGEGRID_ACCOUNT_KEY" description:"Account switch key for authorizing requests"`
	Host            string `long:"host" env:"EDGEGRID_HOST" description:"Edgegrid API host"`
	ClientToken     string `long:"client-token" env:"EDGEGRID_CLIENT_TOKEN" description:"Client token for Edgegrid authentication"`
	ClientSecret    string `long:"client-secret" env:"EDGEGRID_CLIENT_SECRET" description:"Client secret for Edgegrid authentication"`
	AccessToken     string `long:"access-token" env:"EDGEGRID_ACCESS_TOKEN" description:"Access token for Edgegrid authentication"`
}

// edgerc configures and returns an edgegrid.Config object for authentication.
// It prioritizes loading credentials from the specified Edgegrid file, but if the file
// does not exist, it falls back to using credentials provided via command-line flags
// or environment variables.
func (cmd *rootCmd) edgerc() (*edgegrid.Config, error) {
	egpath, err := homedir.Expand(cmd.EdgegridFile)
	if err != nil {
		return nil, err
	}

	var edgerc *edgegrid.Config
	if _, err := os.Stat(egpath); err == nil {
		// Load from .edgerc file if it exists
		edgerc, err = edgegrid.New(
			edgegrid.WithFile(egpath),
			edgegrid.WithSection(cmd.EdgegridSection),
		)
		if err != nil {
			return nil, err
		}
	} else {
		// Fallback to command-line flags or environment variables
		edgerc, _ = edgegrid.New()
		if cmd.Host != "" {
			edgerc.Host = cmd.Host
		}
		if cmd.ClientToken != "" {
			edgerc.ClientToken = cmd.ClientToken
		}
		if cmd.ClientSecret != "" {
			edgerc.ClientSecret = cmd.ClientSecret
		}
		if cmd.AccessToken != "" {
			edgerc.AccessToken = cmd.AccessToken
		}
	}
	// Ensure all required credentials are provided
	if edgerc.Host == "" || edgerc.ClientToken == "" || edgerc.ClientSecret == "" || edgerc.AccessToken == "" {
		return nil, fmt.Errorf("failed to load an edgegrid configuration")
	}

	// Set AccountKey if provided
	if cmd.AccountKey != "" {
		edgerc.AccountKey = cmd.AccountKey
	}

	return edgerc, nil
}

// curlCmd handles the 'curl' subcommand, which signs and sends an HTTP request.
type curlCmd struct {
	URL    string   `long:"url" description:"The URL for the API request."`
	Method string   `short:"X" long:"request" description:"The HTTP method for the request (e.g., GET, POST)." default:"GET"`
	Header []string `short:"H" long:"header" description:"An HTTP header to include in the request. Can be specified multiple times."`
	Data   string   `short:"d" long:"data" description:"The data to send in the request body."`
	Cookie string   `short:"b" long:"cookie" description:"A cookie to send with the request."`

	root *rootCmd `no-flag:"true"`
}

func (cmd *curlCmd) buildRequest(edgerc *edgegrid.Config, args []string) (*http.Request, error) {
	// If the URL is not provided as a flag, use the first positional argument
	if len(args) > 0 && cmd.URL == "" {
		cmd.URL = args[0]
	}

	// Create a new HTTP request
	req, err := http.NewRequest(cmd.Method, cmd.URL, strings.NewReader(cmd.Data))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers to the request
	for _, h := range cmd.Header {
		kv := strings.SplitN(h, ":", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid header format: %q", h)
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		if key == "" {
			return nil, fmt.Errorf("invalid header name in: %q", h)
		}
		req.Header.Add(key, val)
	}

	// Add cookies to the request
	if cmd.Cookie != "" {
		req.Header.Add("Cookie", cmd.Cookie)
	}

	// Parse and set the URL for the request
	if strings.HasPrefix(cmd.URL, "https://") || strings.HasPrefix(cmd.URL, "http://") {
		u, err := url.Parse(cmd.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse url: %w", err)
		}
		req.URL = u
	} else if strings.HasPrefix(cmd.URL, "/") {
		req.URL = &url.URL{Scheme: "https", Host: edgerc.Host, Path: cmd.URL}
	} else {
		return nil, fmt.Errorf("failed to parse url: '%s'", cmd.URL)
	}

	// Set the Content-Type header if data is present
	if cmd.Data != "" {
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
	}

	return req, nil
}

func (cmd *curlCmd) Execute(args []string) error {
	// Load the EdgeGrid configuration
	edgerc, err := cmd.root.edgerc()
	if err != nil {
		return err
	}

	req, err := cmd.buildRequest(edgerc, args)
	if err != nil {
		return err
	}

	// Sign the request with EdgeGrid credentials
	edgerc.SignRequest(req)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read and print the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fmt.Println(string(body))
	return nil
}

// proxyCmd handles the 'proxy' subcommand, which starts a reverse proxy that signs requests.
type proxyCmd struct {
	ProxyAddr    string `short:"a" long:"addr" description:"The address for the proxy server to listen on." default:"127.0.0.1:8080"`
	ProxyTLSCert string `long:"tls-crt" description:"The path to the TLS/SSL certificate file for the proxy."`
	ProxyTLSKey  string `long:"tls-key" description:"The path to the TLS/SSL key file for the proxy."`

	root *rootCmd `no-flag:"true"`
}

func (cmd *proxyCmd) Execute(args []string) error {
	// Load the EdgeGrid configuration
	edgerc, err := cmd.root.edgerc()
	if err != nil {
		return err
	}

	// Determine the proxy scheme based on TLS settings
	var proxyScheme string
	switch {
	case cmd.ProxyTLSCert == "" && cmd.ProxyTLSKey == "":
		proxyScheme = "http"
	case cmd.ProxyTLSCert != "" && cmd.ProxyTLSKey != "":
		proxyScheme = "https"
	default:
		return fmt.Errorf("both --tls-crt and --tls-key must be provided for HTTPS")
	}

	// Set up the reverse proxy
	apiHost := &url.URL{Scheme: "https", Host: edgerc.Host}
	egproxy := httputil.NewSingleHostReverseProxy(apiHost)
	director := egproxy.Director

	// The director function modifies the request before it is sent to the target server
	egproxy.Director = func(req *http.Request) {
		req.Host = apiHost.Host
		director(req)

		// Sign the request with EdgeGrid credentials
		edgerc.SignRequest(req)
		log.Printf("%s %s", req.Method, req.URL.String())
	}

	// The ModifyResponse function allows us to rewrite the Location header in redirects
	egproxy.ModifyResponse = func(resp *http.Response) error {
		loc := resp.Header.Get("Location")
		if loc == "" {
			return nil
		}

		u, err := url.Parse(loc)
		if err != nil {
			return nil
		}

		u.Scheme = proxyScheme
		u.Host = cmd.ProxyAddr

		// Rewrite redirects to point back to the proxy
		resp.Header.Set("Location", u.String())
		return nil
	}

	log.Printf("EdgeGrid ClientToken: %s", edgerc.ClientToken)
	if edgerc.AccountKey != "" {
		log.Printf("EdgeGrid AccountSwitchKey: %s", edgerc.AccountKey)
	}

	log.Printf("Starting EdgeGrid proxy on %s://%s", proxyScheme, cmd.ProxyAddr)
	http.Handle("/", egproxy)

	// Start the proxy server
	if proxyScheme == "https" {
		return http.ListenAndServeTLS(cmd.ProxyAddr, cmd.ProxyTLSCert, cmd.ProxyTLSKey, nil)
	}
	return http.ListenAndServe(cmd.ProxyAddr, nil)
}

func main() {
	// Initialize the root command and parser
	cmd := new(rootCmd)
	parser := flags.NewParser(cmd, flags.HelpFlag|flags.PrintErrors)

	// Register the 'curl' subcommand
	parser.AddCommand("curl", "Make a signed API call", "This command signs and sends an HTTP request to the Akamai API.", &curlCmd{root: cmd})

	// Register the 'proxy' subcommand
	parser.AddCommand("proxy", "Start a signing proxy server", "This command starts a reverse proxy that automatically signs incoming requests and forwards them to the Akamai API.", &proxyCmd{root: cmd})

	// Parse the command-line arguments
	_, err := parser.Parse()
	if err != nil {
		// If the error is a help request, exit gracefully
		if fe, ok := err.(*flags.Error); ok && fe.Type == flags.ErrHelp {
			os.Exit(0)
		}
		// Otherwise, exit with an error
		os.Exit(1)
	}
}

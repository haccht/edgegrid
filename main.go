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

type rootCmd struct {
	EdgegridFile    string `short:"r" long:"file" description:"Location of the Edgegrid configuration file" default:"~/.edgerc"`
	EdgegridSection string `short:"s" long:"section" description:"Section of the Edgegrid configuration file to use" default:"default"`
	AccountKey      string `short:"k" long:"key" env:"EDGEGRID_ACCOUNT_KEY" description:"Account switch key for authorizing requests"`
	Host            string `long:"host" env:"EDGEGRID_HOST" description:"Edgegrid API host"`
	ClientToken     string `long:"client-token" env:"EDGEGRID_CLIENT_TOKEN" description:"Client token for Edgegrid authentication"`
	ClientSecret    string `long:"client-secret" env:"EDGEGRID_CLIENT_SECRET" description:"Client secret for Edgegrid authentication"`
	AccessToken     string `long:"access-token" env:"EDGEGRID_ACCESS_TOKEN" description:"Access token for Edgegrid authentication"`
}

func (cmd *rootCmd) edgerc() (*edgegrid.Config, error) {
	egpath, err := homedir.Expand(cmd.EdgegridFile)
	if err != nil {
		return nil, err
	}

	var edgerc *edgegrid.Config
	if _, err := os.Stat(egpath); err == nil {
		edgerc, err = edgegrid.New(
			edgegrid.WithFile(egpath),
			edgegrid.WithSection(cmd.EdgegridSection),
		)
		if err != nil {
			return nil, err
		}
	} else {
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
	if edgerc.Host == "" || edgerc.ClientToken == "" || edgerc.ClientSecret == "" || edgerc.AccessToken == "" {
		return nil, fmt.Errorf("failed to load an edgegrid configuration")
	}
	if cmd.AccountKey != "" {
		edgerc.AccountKey = cmd.AccountKey
	}

	return edgerc, nil
}

type curlCmd struct {
	Method  string   `short:"X" long:"request" description:"HTTP method"`
	Headers []string `short:"H" long:"header"  description:"Request headers"`
	Data    []string `short:"d" long:"data"    description:"Request body data"`
	Cookies []string `short:"b" long:"cookie"  description:"HTTP cookies"`
	Args    struct {
		Endpoint string `positional-arg-name:"endpoint"`
	} `positional-args:"yes"`

	root *rootCmd `no-flag:"true"`
}

func (cmd *curlCmd) Execute(args []string) error {
	edgerc, err := cmd.root.edgerc()
	if err != nil {
		return err
	}

	if cmd.Args.Endpoint == "" {
		return fmt.Errorf("url is required")
	}

	u, err := url.Parse(cmd.Args.Endpoint)
	if err != nil {
		return fmt.Errorf("failed to parse url: %w", err)
	}
	u.Scheme = "https"
	u.Host = edgerc.Host

	if cmd.Method == "" {
		if len(cmd.Data) > 0 {
			cmd.Method = http.MethodPost
		} else {
			cmd.Method = http.MethodGet
		}
	}

	var reqBody io.Reader
	reqBodyStr := strings.Join(cmd.Data, "&")
	if reqBodyStr != "" {
		reqBody = strings.NewReader(reqBodyStr)
	}

	req, err := http.NewRequest(cmd.Method, u.String(), reqBody)
	if err != nil {
		return err
	}

	for _, kv := range cmd.Headers {
		colon := strings.IndexByte(kv, ':')
		if colon <= 0 {
			return fmt.Errorf("invalid header format: %q", kv)
		}

		key := strings.TrimSpace(kv[:colon])
		val := strings.TrimSpace(kv[colon+1:])
		if key == "" {
			return fmt.Errorf("invalid header name in: %q", kv)
		}
		req.Header.Add(key, val)
	}

	for _, c := range cmd.Cookies {
		req.Header.Add("Cookie", c)
	}

	if reqBodyStr != "" {
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
		req.ContentLength = int64(len(reqBodyStr))
	}

	//sign request
	edgerc.SignRequest(req)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fmt.Println(string(body))
	return nil
}

type proxyCmd struct {
	ProxyAddr    string `short:"a" long:"addr" description:"The address for the proxy server to listen on." default:"127.0.0.1:8080"`
	ProxyTLSCert string `long:"tls-crt" description:"The path to the TLS/SSL certificate file for the proxy."`
	ProxyTLSKey  string `long:"tls-key" description:"The path to the TLS/SSL key file for the proxy."`

	root *rootCmd `no-flag:"true"`
}

func (cmd *proxyCmd) Execute(args []string) error {
	edgerc, err := cmd.root.edgerc()
	if err != nil {
		return err
	}

	var proxyScheme string
	switch {
	case cmd.ProxyTLSCert == "" && cmd.ProxyTLSKey == "":
		proxyScheme = "http"
	case cmd.ProxyTLSCert != "" && cmd.ProxyTLSKey != "":
		proxyScheme = "https"
	default:
		return fmt.Errorf("both --tls-crt and --tls-key must be provided for HTTPS")
	}

	apiHost := &url.URL{Scheme: "https", Host: edgerc.Host}
	egproxy := httputil.NewSingleHostReverseProxy(apiHost)
	director := egproxy.Director

	egproxy.Director = func(req *http.Request) {
		req.Host = apiHost.Host
		director(req)

		//sign request
		edgerc.SignRequest(req)
		log.Printf("%s %s", req.Method, req.URL.String())
	}

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

		resp.Header.Set("Location", u.String())
		return nil
	}

	log.Printf("Edgegrid ClientToken: %s", edgerc.ClientToken)
	if edgerc.AccountKey != "" {
		log.Printf("Edgegrid AccountSwitchKey: %s", edgerc.AccountKey)
	}

	log.Printf("Starting Edgegrid proxy on %s://%s", proxyScheme, cmd.ProxyAddr)
	http.Handle("/", egproxy)

	if proxyScheme == "https" {
		return http.ListenAndServeTLS(cmd.ProxyAddr, cmd.ProxyTLSCert, cmd.ProxyTLSKey, nil)
	}
	return http.ListenAndServe(cmd.ProxyAddr, nil)
}

func main() {
	cmd := new(rootCmd)
	parser := flags.NewParser(cmd, flags.HelpFlag|flags.PrintErrors)

	parser.AddCommand(
		"curl",
		"Make a signed API call",
		"This command signs and sends an HTTP request to the Akamai API.",
		&curlCmd{root: cmd},
	)

	parser.AddCommand(
		"proxy",
		"Start a signing proxy server",
		"This command starts a reverse proxy that automatically signs incoming requests and forwards them to the Akamai API.",
		&proxyCmd{root: cmd},
	)

	_, err := parser.Parse()
	if err != nil {
		if fe, ok := err.(*flags.Error); ok && fe.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}
}

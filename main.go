package main

import (
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
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
	EdgegridFile    string `short:"r" long:"file" description:"Location of Edgegrid file" default:"~/.edgerc"`
	EdgegridSection string `short:"s" long:"section" description:"Section of Edgegrid file" default:"default"`
	AccountKey      string `short:"k" long:"key" env:"EDGEGRID_ACCOUNT_KEY" description:"Account switch key"`
	Host            string `long:"host" env:"EDGEGRID_HOST" description:"Edgegrid Host"`
	ClientToken     string `long:"client-token" env:"EDGEGRID_CLIENT_TOKEN" description:"Edgegrid ClientToken"`
	ClientSecret    string `long:"client-secret" env:"EDGEGRID_CLIENT_SECRET" description:"Edgegrid ClientSecret"`
	AccessToken     string `long:"access-token" env:"EDGEGRID_ACCESS_TOKEN" description:"Edgegrid AccessToken"`
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
	root *rootCmd `no-flag:"true"`
}

func (cmd *curlCmd) Execute(args []string) error {
	req, err := cmd.newRequest(args)
	if err != nil {
		return err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fmt.Println(string(body))
	return nil
}

func (cmd *curlCmd) newRequest(parts []string) (*http.Request, error) {
	edgerc, err := cmd.root.edgerc()
	if err != nil {
		return nil, err
	}

	var urlStr string
	var bodyParts []string

	req := &http.Request{Header: make(http.Header)}
	for i := 0; i < len(parts); i++ {
		val := parts[i]
		if val == "curl" && i == 0 {
			continue
		}

		switch val {
		case "--url":
			i++
			if i >= len(parts) {
				return nil, fmt.Errorf("%s requires argument", val)
			}

			urlStr = parts[i]
		case "-X", "--request", "--method":
			i++
			if i >= len(parts) {
				return nil, fmt.Errorf("%s requires argument", val)
			}

			req.Method = parts[i]
		case "-H", "--header":
			i++
			if i >= len(parts) {
				return nil, fmt.Errorf("%s requires argument", val)
			}

			kv := parts[i]
			colon := strings.IndexByte(kv, ':')
			if colon <= 0 {
				return nil, fmt.Errorf("invalid header format: %q", kv)
			}

			key := strings.TrimSpace(kv[:colon])
			val := strings.TrimSpace(kv[colon+1:])
			if key == "" {
				return nil, fmt.Errorf("invalid header name in: %q", kv)
			}
			req.Header.Add(key, val)
		case "-d", "--data", "--data-raw", "--data-binary":
			i++
			if i >= len(parts) {
				return nil, fmt.Errorf("%s requires argument", val)
			}

			bodyParts = append(bodyParts, parts[i])
		case "-b", "--cookie":
			i++
			if i >= len(parts) {
				return nil, fmt.Errorf("%s requires argument", val)
			}

			req.Header.Add("Cookie", parts[i])
		default:
			if strings.HasPrefix(val, "-") {
				log.Printf("ignore unsupported curl flag: %s", val)
				continue
			}

			if urlStr == "" {
				urlStr = val
			}
		}
	}

	if strings.HasPrefix(urlStr, "https://") || strings.HasPrefix(urlStr, "http://") {
		url, err := url.Parse(urlStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse url: %w", err)
		}

		req.URL = url
		req.URL.Scheme = "https"
		req.URL.Host = edgerc.Host
	} else if strings.HasPrefix(urlStr, "/") {
		req.URL = &url.URL{Scheme: "https", Host: edgerc.Host, Path: urlStr}
	} else {
		return nil, fmt.Errorf("failed to parse url: '%s'", urlStr)
	}

	var bodyReader io.Reader
	bodyStr := strings.Join(bodyParts, "&")
	if req.Method == "" {
		if len(bodyParts) > 0 {
			req.Method = http.MethodPost
		} else {
			req.Method = http.MethodGet
		}
	}

	if bodyStr != "" {
		bodyReader = strings.NewReader(bodyStr)
		contentType := req.Header.Get("Content-Type")

		if contentType == "" {
			contentType = "application/json"
			req.Header.Add("Content-Type", contentType)
		}
		if contentType != "" {
			var params map[string]string
			contentType, params, err = mime.ParseMediaType(contentType)
			if err != nil {
				return nil, fmt.Errorf("failed to parse content type: %w", err)
			}

			switch contentType {
			case "multipart/form-data":
				mpReader := multipart.NewReader(bodyReader, params["boundary"])
				req.MultipartForm, err = mpReader.ReadForm(1024 * 1024)
				if err != nil {
					return nil, fmt.Errorf("failed to parse form data: %w", err)
				}
			default:
				req.Body = io.NopCloser(bodyReader)
				req.ContentLength = int64(len(bodyStr))
			}
		}
	}

	edgerc.SignRequest(req)
	return req, nil
}

type proxyCmd struct {
	ProxyAddr    string `short:"a" long:"addr" description:"Proxy host address" default:"127.0.0.1:8080"`
	ProxyTLSCert string `long:"tls-crt" description:"Proxy TLS/SSL certificate file path"`
	ProxyTLSKey  string `long:"tls-key" description:"Proxy TLS/SSL key file path"`

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
		return fmt.Errorf("either --tls-cert or --tls-key is enabled")
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

		//rewrite redirects
		resp.Header.Set("Location", u.String())
		return nil
	}

	log.Printf("EdgeGrid ClientToken: %s", edgerc.ClientToken)
	if edgerc.AccountKey != "" {
		log.Printf("EdgeGrid AccountSwitchKey: %s", edgerc.AccountKey)
	}

	log.Printf("Starting EdgeGrid proxy on %s://%s", proxyScheme, cmd.ProxyAddr)
	http.Handle("/", egproxy)

	if proxyScheme == "https" {
		return http.ListenAndServeTLS(cmd.ProxyAddr, cmd.ProxyTLSCert, cmd.ProxyTLSKey, nil)
	}
	return http.ListenAndServe(cmd.ProxyAddr, nil)
}

func main() {
	cmd := new(rootCmd)
	parser := flags.NewParser(cmd, flags.HelpFlag|flags.PrintErrors|flags.IgnoreUnknown)
	parser.AddCommand("curl", "Make the API call with the computed request signature", "", &curlCmd{root: cmd})
	parser.AddCommand("proxy", "Start a proxy server to sign API call requests", "", &proxyCmd{root: cmd})

	_, err := parser.Parse()
	if err != nil {
		if fe, ok := err.(*flags.Error); ok && fe.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}
}

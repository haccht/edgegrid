package cmd

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var knownFlags = map[string]bool{
	"--url": true,
	"-X":    true, "--request": true,
	"-H": true, "--header": true,
	"-d": true, "--data": true,
	"--data-binary": true,
	"--data-ascii":  true,
	"--data-raw":    true,
}

func splitKnownArgs(args []string) ([]string, []string) {
	var known, unknown []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--") {
			if eq := strings.Index(arg, "="); eq > 0 {
				if knownFlags[arg[:eq]] {
					known = append(known, arg)
				} else {
					unknown = append(unknown, arg)
				}
				continue
			}
			if knownFlags[arg] {
				known = append(known, arg)
				if i+1 < len(args) {
					known = append(known, args[i+1])
					i++
				}
				continue
			}
		} else if strings.HasPrefix(arg, "-") {
			for flag := range knownFlags {
				if strings.HasPrefix(arg, flag) && len(flag) < len(arg) {
					known = append(known, arg)
					continue
				}
			}
			if knownFlags[arg] {
				known = append(known, arg)
				if i+1 < len(args) {
					known = append(known, args[i+1])
					i++
				}
				continue
			}
		}
		unknown = append(unknown, arg)
	}
	return known, unknown
}

type requestData struct {
	values            []string
	joinWithAmpersand bool
	removeNewlines    bool
}

func buildRequestBody(cfg requestData) ([]byte, bool, error) {
	if len(cfg.values) == 1 && strings.HasPrefix(cfg.values[0], "@") {
		path := strings.TrimPrefix(cfg.values[0], "@")
		if path == "-" {
			body, err := io.ReadAll(os.Stdin)
			if err != nil {
				return nil, false, fmt.Errorf("failed to read request body from stdin: %w", err)
			}

			if cfg.removeNewlines {
				body = removeNewlinesReplaceAll(body)
			}
			return body, true, nil
		}

		fileContent, err := os.ReadFile(path)
		if err != nil {
			return nil, false, fmt.Errorf("failed to read data file %q: %w", path, err)
		}

		if cfg.removeNewlines {
			fileContent = removeNewlinesReplaceAll(fileContent)
		}
		return fileContent, false, nil
	}

	separator := ""
	if cfg.joinWithAmpersand {
		separator = "&"
	}

	return []byte(strings.Join(cfg.values, separator)), false, nil
}

func removeNewlinesReplaceAll(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte{'\r'}, nil)
	data = bytes.ReplaceAll(data, []byte{'\n'}, nil)
	return data
}

var curlCmd = &cobra.Command{
	Use:                "curl [endpoint]",
	Short:              "Signs and sends a single HTTP request.",
	Long:               "This command signs and sends a single HTTP request to the Akamai API, similar to the standard curl command.",
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			endpoint string
			method   string
			headers  []string
			data     []string
			dataBin  []string
		)

		knownArgs, unknownArgs := splitKnownArgs(args)

		fs := pflag.NewFlagSet("curl", pflag.ContinueOnError)
		fs.StringVar(&endpoint, "url", "", "The URL for the request.")
		fs.StringVarP(&method, "request", "X", "", "The HTTP method to use.")
		fs.StringArrayVarP(&headers, "header", "H", nil, "An HTTP header to include in the request.")
		fs.StringArrayVarP(&data, "data", "d", nil, "The data to send in the request body.")
		fs.StringArrayVar(&dataBin, "data-binary", nil, "The data to send in the request body without processing.")
		fs.StringArrayVar(&data, "data-ascii", nil, "ASCII data to send in the request body.")
		fs.StringArrayVar(&data, "data-raw", nil, "The data to send in the request body without @file processing.")
		if err := fs.Parse(knownArgs); err != nil {
			return fmt.Errorf("curl: %s", err)
		}

		rawEndpoint := endpoint
		if endpoint == "" && len(unknownArgs) > 0 {
			for _, v := range unknownArgs {
				s := strings.Trim(v, `"'`)
				if strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "/") {
					rawEndpoint = v
					endpoint = s
				}
			}
		}
		if endpoint == "" {
			return fmt.Errorf("an endpoint URL must be provided either as an argument or with the --url flag")
		}

		edSigner, err := egOption.Signer()
		if err != nil {
			return err
		}

		u, err := url.Parse(endpoint)
		if err != nil {
			return fmt.Errorf("failed to parse endpoint URL: %w", err)
		}
		u.Scheme = "https"
		u.Host = edSigner.Host

		var bodyCfg *requestData
		switch {
		case len(dataBin) > 0 && len(data) > 0:
			return fmt.Errorf("multiple data payload options provided; please use only one of --data or --data-binary")
		case len(dataBin) > 0:
			bodyCfg = &requestData{values: dataBin}
		case len(data) > 0:
			bodyCfg = &requestData{values: data, joinWithAmpersand: true, removeNewlines: true}
		}

		if method == "" {
			if bodyCfg != nil {
				method = http.MethodPost
			} else {
				method = http.MethodGet
			}
		}

		var reqBody io.Reader
		var contentLength int64
		var stdinBody []byte
		var usesStdin bool
		if bodyCfg != nil {
			body, fromStdin, err := buildRequestBody(*bodyCfg)
			if err != nil {
				return err
			}
			reqBody = bytes.NewReader(body)
			contentLength = int64(len(body))
			stdinBody = body
			usesStdin = fromStdin
		}

		req, err := http.NewRequest(method, u.String(), reqBody)
		if err != nil {
			return fmt.Errorf("failed to create new HTTP request: %w", err)
		}

		for _, kv := range headers {
			parts := strings.SplitN(kv, ":", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid header format: %q (expected 'key:value')", kv)
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if key == "" {
				return fmt.Errorf("invalid header name in: %q", kv)
			}
			req.Header.Add(key, val)
		}

		if contentLength > 0 {
			req.ContentLength = contentLength
		}

		edSigner.SignRequest(req)

		curlPath, err := exec.LookPath("curl")
		if err != nil {
			for _, arg := range unknownArgs {
				if strings.HasPrefix(arg, "-") && arg != "-" && arg != "--" {
					fmt.Fprintf(os.Stderr, "unsupported flag: %s", arg)
				}
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("failed to execute HTTP request: %w", err)
			}
			defer resp.Body.Close()

			_, err = io.Copy(os.Stdout, resp.Body)
			if err != nil {
				return err
			}
			return nil
		}

		curlArgs := os.Args[slices.Index(os.Args, "curl")+1:]
		curlArgs[slices.Index(curlArgs, rawEndpoint)] = req.URL.String()

		authHeader := fmt.Sprintf("Authorization: %s", req.Header.Get("Authorization"))
		curlArgs = append(curlArgs, "-H", authHeader)

		c := exec.Command(curlPath, curlArgs...)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if usesStdin {
			c.Stdin = bytes.NewReader(stdinBody)
		}

		if err := c.Run(); err != nil {
			if exitError, ok := err.(*exec.ExitError); ok {
				os.Exit(exitError.ExitCode())
			}
			return err
		}
		return nil
	},
}

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
	"-b": true, "--cookie": true,
	"-d": true, "--data": true,
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
			cookies  []string
			data     []string
		)

		knownArgs, unknownArgs := splitKnownArgs(args)

		fs := pflag.NewFlagSet("curl", pflag.ContinueOnError)
		fs.StringVar(&endpoint, "url", "", "The URL for the request.")
		fs.StringVarP(&method, "request", "X", "", "The HTTP method to use.")
		fs.StringArrayVarP(&headers, "header", "H", nil, "An HTTP header to include in the request.")
		fs.StringArrayVarP(&cookies, "cookie", "b", nil, "A cookie to send with the request.")
		fs.StringArrayVarP(&data, "data", "d", nil, "The data to send in the request body.")
		if err := fs.Parse(knownArgs); err != nil {
			return fmt.Errorf("curl: %s", err)
		}

		if endpoint == "" && len(unknownArgs) > 0 {
			for _, v := range unknownArgs {
				if strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "/") {
					endpoint = v
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

		if method == "" {
			if len(data) > 0 {
				method = http.MethodPost
			} else {
				method = http.MethodGet
			}
		}

		var reqBody io.Reader
		var contentLength int64
		if len(data) > 0 {
			if len(data) == 1 && strings.HasPrefix(data[0], "@") {
				filePath := strings.TrimPrefix(data[0], "@")
				fileContent, err := os.ReadFile(filePath)
				if err != nil {
					return fmt.Errorf("failed to read data file %q: %w", filePath, err)
				}
				reqBody = bytes.NewReader(fileContent)
				contentLength = int64(len(fileContent))
			} else {
				reqBodyStr := strings.Join(data, "&")
				reqBody = strings.NewReader(reqBodyStr)
				contentLength = int64(len(reqBodyStr))
			}
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

		for _, c := range cookies {
			req.Header.Add("Cookie", c)
		}

		if contentLength > 0 {
			req.ContentLength = contentLength
		}

		edSigner.SignRequest(req)

		curlPath, err := exec.LookPath("curl")
		if err != nil {
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
		curlArgs[slices.Index(curlArgs, endpoint)] = req.URL.String()

		authHeader := fmt.Sprintf("Authorization: %s", req.Header.Get("Authorization"))
		curlArgs = append(curlArgs, "-H", authHeader)

		c := exec.Command(curlPath, curlArgs...)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		return c.Run()
	},
}

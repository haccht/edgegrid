package cmd

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	method   string
	headers  []string
	cookies  []string
	data     []string
	endpoint string
)

var curlCmd = &cobra.Command{
	Use:   "curl [endpoint]",
	Short: "Signs and sends a single HTTP request.",
	Long:  "This command signs and sends a single HTTP request to the Akamai API, similar to the standard curl command.",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if endpoint == "" && len(args) > 0 {
			endpoint = args[0]
		} else if endpoint == "" {
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
			if req.Header.Get("Content-Type") == "" {
				req.Header.Set("Content-Type", "application/json")
			}
			req.ContentLength = contentLength
		}

		edSigner.SignRequest(req)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to execute HTTP request: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}

		fmt.Println(string(body))
		return nil
	},
}

func init() {
	curlCmd.Flags().StringVarP(&method, "request", "X", "", "The HTTP method to use.")
	curlCmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "An HTTP header to include in the request.")
	curlCmd.Flags().StringArrayVarP(&data, "data", "d", nil, "The data to send in the request body.")
	curlCmd.Flags().StringArrayVarP(&cookies, "cookie", "b", nil, "A cookie to send with the request.")
	curlCmd.Flags().StringVar(&endpoint, "url", "", "The URL for the request.")
}

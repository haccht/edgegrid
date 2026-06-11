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
	"-h": true, "--help": true,
	"--data-ascii": true, "--data-binary": true, "--data-raw": true,
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

type reqDataItem struct {
	value    string
	isRaw    bool
	isBinary bool
}

type reqData struct {
	items []reqDataItem
}

func (c *reqData) Read() ([]byte, error) {
	if len(c.items) == 0 {
		return nil, nil
	}

	var body []byte
	for i, item := range c.items {
		if i > 0 {
			body = append(body, '&')
		}

		part, err := item.Read()
		if err != nil {
			return nil, err
		}
		body = append(body, part...)
	}

	return body, nil
}

func (i reqDataItem) Read() ([]byte, error) {
	if i.isRaw || !strings.HasPrefix(i.value, "@") {
		return []byte(i.value), nil
	}

	var reader io.Reader
	filepath := strings.TrimPrefix(i.value, "@")
	if filepath == "-" {
		reader = os.Stdin
	} else {
		fd, err := os.Open(filepath)
		if err != nil {
			return nil, fmt.Errorf("failed to open file %q: %w", filepath, err)
		}
		defer fd.Close()

		reader = fd
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}

	if !i.isBinary {
		body = bytes.ReplaceAll(body, []byte("\n"), []byte{})
		body = bytes.ReplaceAll(body, []byte("\r"), []byte{})
	}
	return body, nil
}

type reqDataValue struct {
	items    *[]reqDataItem
	isBinary bool
	isRaw    bool
}

func (v reqDataValue) Set(s string) error {
	*v.items = append(*v.items, reqDataItem{
		value:    s,
		isBinary: v.isBinary,
		isRaw:    v.isRaw,
	})
	return nil
}

func (v reqDataValue) String() string {
	if v.items == nil {
		return ""
	}

	values := make([]string, 0, len(*v.items))
	for _, item := range *v.items {
		values = append(values, item.value)
	}
	return strings.Join(values, "&")
}

func (reqDataValue) Type() string {
	return "stringArray"
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
			data     []reqDataItem
		)

		knownArgs, unknownArgs := splitKnownArgs(args)

		fs := pflag.NewFlagSet("curl", pflag.ContinueOnError)
		fs.StringVar(&endpoint, "url", "", "The URL for the request.")
		fs.StringVarP(&method, "request", "X", "", "The HTTP method to use.")
		fs.StringArrayVarP(&headers, "header", "H", nil, "An HTTP header to include in the request.")
		fs.VarP(reqDataValue{items: &data}, "data", "d", "The data to send in the request body.")
		fs.Var(reqDataValue{items: &data}, "data-ascii", "The data to send in the request body.")
		fs.Var(reqDataValue{items: &data, isBinary: true}, "data-binary", "The binary data to send in the request body.")
		fs.Var(reqDataValue{items: &data, isRaw: true}, "data-raw", "The data to send in the request body without special @ handling.")
		if err := fs.Parse(knownArgs); err != nil {
			return fmt.Errorf("curl: %s", err)
		}

		rawEndpoint := endpoint
		if endpoint == "" && len(unknownArgs) > 0 {
			for _, v := range unknownArgs {
				s := strings.Trim(v, `"':`)
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
		if method == "" {
			if len(data) > 0 {
				method = http.MethodPost
			} else {
				method = http.MethodGet
			}
		}

		var bodyBytes []byte
		var bodyReader io.Reader

		if len(data) > 0 {
			rd := &reqData{items: data}
			bodyBytes, err = rd.Read()
			if err != nil {
				return err
			}
			bodyReader = bytes.NewReader(bodyBytes)
		}

		req, err := http.NewRequest(method, u.String(), bodyReader)
		if err != nil {
			return fmt.Errorf("failed to create new HTTP request: %w", err)
		}

		for _, kv := range headers {
			parts := strings.SplitN(kv, ":", 2)
			if len(parts) != 2 || parts[0] == "" {
				return fmt.Errorf("invalid header format: %q (expected 'key:value')", kv)
			}

			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			req.Header.Add(key, val)
		}
		if method == http.MethodPut || method == http.MethodPost {
			req.Header.Add("Expect:", "")
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
		if len(bodyBytes) > 0 {
			c.Stdin = bytes.NewReader(bodyBytes)
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

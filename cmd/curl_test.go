package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func TestReqDataReadRawDoesNotInterpretAt(t *testing.T) {
	body, err := (&reqData{items: []reqDataItem{
		{value: "@missing-file", isRaw: true},
	}}).Read()
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(body), "@missing-file"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestReqDataReadDataFileStripsNewlines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "body.txt")
	if err := os.WriteFile(path, []byte("a\nb\rc\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	body, err := (&reqData{items: []reqDataItem{
		{value: "@" + path},
	}}).Read()
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(body), "abc"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestReqDataReadBinaryFileKeepsNewlines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "body.bin")
	want := []byte("a\nb\rc\r\n")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}

	body, err := (&reqData{items: []reqDataItem{
		{value: "@" + path, isBinary: true},
	}}).Read()
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(body, want) {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

func TestReqDataReadJoinsMultipleValues(t *testing.T) {
	body, err := (&reqData{items: []reqDataItem{
		{value: "a=1"},
		{value: "b=2", isRaw: true},
	}}).Read()
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(body), "a=1&b=2"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestSplitKnownArgsHandlesDataRaw(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantKnown   []string
		wantUnknown []string
	}{
		{
			name:        "space separated",
			args:        []string{"--data-raw", "@literal", "/path"},
			wantKnown:   []string{"--data-raw", "@literal"},
			wantUnknown: []string{"/path"},
		},
		{
			name:        "equals separated",
			args:        []string{"--data-raw=@literal", "/path"},
			wantKnown:   []string{"--data-raw=@literal"},
			wantUnknown: []string{"/path"},
		},
		{
			name:        "attached short flag method",
			args:        []string{"-XPOST", "/path"},
			wantKnown:   []string{"-XPOST"},
			wantUnknown: []string{"/path"},
		},
		{
			name:        "attached short flag header",
			args:        []string{"-HContent-Type: application/json", "/path"},
			wantKnown:   []string{"-HContent-Type: application/json"},
			wantUnknown: []string{"/path"},
		},
		{
			name:        "space separated short flag",
			args:        []string{"-X", "POST", "-d", "data", "/path"},
			wantKnown:   []string{"-X", "POST", "-d", "data"},
			wantUnknown: []string{"/path"},
		},
		{
			name:        "help flag does not consume next arg",
			args:        []string{"-h", "/path"},
			wantKnown:   []string{"-h"},
			wantUnknown: []string{"/path"},
		},
		{
			name:        "unknown flags preserved",
			args:        []string{"-s", "-v", "--insecure", "/path"},
			wantKnown:   nil,
			wantUnknown: []string{"-s", "-v", "--insecure", "/path"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKnown, gotUnknown := splitKnownArgs(tt.args)
			if !reflect.DeepEqual(gotKnown, tt.wantKnown) {
				t.Fatalf("known = %#v, want %#v", gotKnown, tt.wantKnown)
			}
			if !reflect.DeepEqual(gotUnknown, tt.wantUnknown) {
				t.Fatalf("unknown = %#v, want %#v", gotUnknown, tt.wantUnknown)
			}
		})
	}
}

func TestSplitKnownArgsHandlesDryRun(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantKnown   []string
		wantUnknown []string
	}{
		{
			name:        "dry-run before endpoint",
			args:        []string{"--dry-run", "/path"},
			wantKnown:   []string{"--dry-run"},
			wantUnknown: []string{"/path"},
		},
		{
			name:        "dry-run after endpoint",
			args:        []string{"/path", "--dry-run"},
			wantKnown:   []string{"--dry-run"},
			wantUnknown: []string{"/path"},
		},
		{
			name:        "dry-run with equals",
			args:        []string{"--dry-run=true", "/path"},
			wantKnown:   []string{"--dry-run=true"},
			wantUnknown: []string{"/path"},
		},
		{
			name:        "dry-run mixed with other flags",
			args:        []string{"-X", "POST", "--dry-run", "-d", "data", "/path"},
			wantKnown:   []string{"-X", "POST", "--dry-run", "-d", "data"},
			wantUnknown: []string{"/path"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKnown, gotUnknown := splitKnownArgs(tt.args)
			if !reflect.DeepEqual(gotKnown, tt.wantKnown) {
				t.Fatalf("known = %#v, want %#v", gotKnown, tt.wantKnown)
			}
			if !reflect.DeepEqual(gotUnknown, tt.wantUnknown) {
				t.Fatalf("unknown = %#v, want %#v", gotUnknown, tt.wantUnknown)
			}
		})
	}
}

func TestFormatCurlCommand(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "basic command",
			args: []string{"-X", "POST", "https://example.com/api"},
			want: "curl -X POST https://example.com/api",
		},
		{
			name: "escapes spaces and semicolons",
			args: []string{"-H", "Authorization: EG1-HMAC-SHA256 client_token=xxx;nonce=yyy"},
			want: "curl -H 'Authorization: EG1-HMAC-SHA256 client_token=xxx;nonce=yyy'",
		},
		{
			name: "escapes single quotes in JSON",
			args: []string{"-d", `{"name":"O'Reilly"}`},
			want: `curl -d '{"name":"O'\''Reilly"}'`,
		},
		{
			name: "escapes URL with query params",
			args: []string{"https://example.com/api?foo=1&bar=2"},
			want: "curl 'https://example.com/api?foo=1&bar=2'",
		},
		{
			name: "empty arg",
			args: []string{""},
			want: "curl ''",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatCurlCommand(tt.args)
			if got != tt.want {
				t.Fatalf("formatCurlCommand() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCurlCmdDryRun(t *testing.T) {
	viper.Set("host", "example.akamaiapis.net")
	viper.Set("client-token", "test-client-token")
	viper.Set("client-secret", "test-client-secret")
	viper.Set("access-token", "test-access-token")
	defer func() {
		viper.Set("host", "")
		viper.Set("client-token", "")
		viper.Set("client-secret", "")
		viper.Set("access-token", "")
	}()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"curl", "--dry-run", "-X", "POST", "-d", "hello", "/test"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(out, "curl ") {
		t.Errorf("output does not start with 'curl ': %s", out)
	}
	if strings.Contains(out, "--dry-run") {
		t.Errorf("output should not contain --dry-run: %s", out)
	}
	if !strings.Contains(out, "https://example.akamaiapis.net/test") {
		t.Errorf("output does not contain target URL: %s", out)
	}
	if !strings.Contains(out, "-X POST") {
		t.Errorf("output does not contain method: %s", out)
	}
	if !strings.Contains(out, "-d hello") {
		t.Errorf("output does not contain body: %s", out)
	}
	if !strings.Contains(out, "-H 'Authorization: EG1-HMAC-SHA256 client_token=test-client-token;") {
		t.Errorf("output does not contain signed Authorization header: %s", out)
	}
}

func TestReqDataValuePreservesFlagOrder(t *testing.T) {
	var data []reqDataItem
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.VarP(reqDataValue{items: &data}, "data", "d", "")
	fs.Var(reqDataValue{items: &data, isBinary: true}, "data-binary", "")
	fs.Var(reqDataValue{items: &data, isRaw: true}, "data-raw", "")

	if err := fs.Parse([]string{"--data-raw", "@raw", "--data-binary", "@bin", "-d", "@file"}); err != nil {
		t.Fatal(err)
	}

	want := []reqDataItem{
		{value: "@raw", isRaw: true},
		{value: "@bin", isBinary: true},
		{value: "@file"},
	}
	if !reflect.DeepEqual(data, want) {
		t.Fatalf("data = %#v, want %#v", data, want)
	}
}

func TestCurlCmdHelpFlag(t *testing.T) {
	for _, flag := range []string{"-h", "--help"} {
		t.Run(flag, func(t *testing.T) {
			buf := new(bytes.Buffer)
			rootCmd.SetOut(buf)
			rootCmd.SetErr(buf)
			rootCmd.SetArgs([]string{"curl", flag})

			err := rootCmd.Execute()
			if err != nil {
				t.Fatalf("unexpected error for %s: %v", flag, err)
			}
			output := buf.String()
			for _, expected := range []string{"Usage:", "--url", "--data", "-X", "-H", "-h, --help", "--dry-run"} {
				if !strings.Contains(output, expected) {
					t.Errorf("output does not contain %q: %s", expected, output)
				}
			}
		})
	}
}

func TestRootCmdHelpOutput(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)

	err := rootCmd.Help()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()
	for _, expected := range []string{"curl", "proxy", "--file", "--section", "--host", "-h, --help"} {
		if !strings.Contains(output, expected) {
			t.Errorf("output does not contain %q: %s", expected, output)
		}
	}
}

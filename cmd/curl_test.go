package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/spf13/pflag"
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

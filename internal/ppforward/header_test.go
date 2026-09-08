package ppforward

import (
	"net"
	"os"
	"testing"
)

func TestFormatProxyHeaderV1(t *testing.T) {
	client := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 54321}
	server := &net.TCPAddr{IP: net.ParseIP("198.51.100.5"), Port: 2053}

	got, err := FormatProxyHeaderV1(client, server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "PROXY TCP4 203.0.113.10 198.51.100.5 54321 2053\r\n"
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestFormatProxyHeaderV1RejectsIPv6Client(t *testing.T) {
	client := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234}
	server := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2054}

	_, err := FormatProxyHeaderV1(client, server)
	if err == nil {
		t.Fatal("expected ipv4-only error")
	}
}

func TestLoadConfig(t *testing.T) {
	path := t.TempDir() + "/config.json"
	content := []byte(`{"rules":[{"listen":"0.0.0.0:2053","target":"127.0.0.1:2054","tag":"inbound-1"}]}`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0].Tag != "inbound-1" {
		t.Fatalf("unexpected cfg: %+v", cfg)
	}
}

func TestLoadConfigRequiresListenAndTarget(t *testing.T) {
	path := t.TempDir() + "/config.json"
	if err := os.WriteFile(path, []byte(`{"rules":[{"listen":"0.0.0.0:2053"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected validation error")
	}
}

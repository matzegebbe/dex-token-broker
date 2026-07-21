package main

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestApplicationStartsAndShutsDown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve startup test address: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release startup test address: %v", err)
	}

	var output bytes.Buffer
	cmd := exec.Command(os.Args[0], "-test.run=^TestApplicationHelperProcess$")
	cmd.Env = []string{
		"DEXTOKENBROKER_STARTUP_HELPER=1",
		"LISTEN_ADDR=" + address,
		"DEX_TOKEN_URL=https://dex.example/token",
		"LOG_LEVEL=error",
	}
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Start(); err != nil {
		t.Fatalf("start application process: %v", err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})

	client := &http.Client{Timeout: 200 * time.Millisecond}
	healthURL := "http://" + address + "/healthz"
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, requestErr := client.Get(healthURL)
		if requestErr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}

		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("application did not become healthy: %v\n%s", requestErr, output.String())
		}
		time.Sleep(25 * time.Millisecond)
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal application process: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("application did not shut down cleanly: %v\n%s", err, output.String())
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("application did not shut down within 5 seconds\n%s", output.String())
	}
}

func TestApplicationHelperProcess(t *testing.T) {
	if os.Getenv("DEXTOKENBROKER_STARTUP_HELPER") != "1" {
		return
	}

	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "application startup failed: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestParseJWKSProviders(t *testing.T) {
	t.Run("empty input yields nil", func(t *testing.T) {
		providers, err := parseJWKSProviders("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if providers != nil {
			t.Fatalf("expected nil providers, got %v", providers)
		}
	})

	t.Run("string and array audiences", func(t *testing.T) {
		raw := `[
			{"url":"https://a.example/jwks","issuer":"https://a.example/","audience":"api-a"},
			{"url":"https://b.example/jwks","audience":["api-b","api-b2"]}
		]`
		providers, err := parseJWKSProviders(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(providers) != 2 {
			t.Fatalf("expected 2 providers, got %d", len(providers))
		}
		if providers[0].URL != "https://a.example/jwks" {
			t.Fatalf("unexpected url: %q", providers[0].URL)
		}
		if len(providers[0].Issuers) != 1 || providers[0].Issuers[0] != "https://a.example/" {
			t.Fatalf("unexpected issuers: %v", providers[0].Issuers)
		}
		if len(providers[0].Audiences) != 1 || providers[0].Audiences[0] != "api-a" {
			t.Fatalf("unexpected audiences: %v", providers[0].Audiences)
		}
		if len(providers[1].Audiences) != 2 {
			t.Fatalf("expected 2 audiences for array form, got %v", providers[1].Audiences)
		}
		if len(providers[1].Issuers) != 0 {
			t.Fatalf("expected no issuers when omitted, got %v", providers[1].Issuers)
		}
	})

	t.Run("missing url is rejected", func(t *testing.T) {
		_, err := parseJWKSProviders(`[{"audience":"api-a"}]`)
		if err == nil {
			t.Fatal("expected error for entry without url")
		}
	})

	t.Run("invalid JSON is rejected", func(t *testing.T) {
		_, err := parseJWKSProviders(`{not json`)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})
}

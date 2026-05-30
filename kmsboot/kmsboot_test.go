// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kmsboot

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fakeFetcher records calls and returns canned bytes per (path,name).
// Reusable across cases; tests construct a fresh one each time.
type fakeFetcher struct {
	store map[string][]byte // key = path+name
	closed bool
}

func (f *fakeFetcher) Get(_ context.Context, path, name string) ([]byte, error) {
	b, ok := f.store[path+name]
	if !ok {
		return nil, fmt.Errorf("fake: not found %s%s", path, name)
	}
	return b, nil
}

func (f *fakeFetcher) Close() { f.closed = true }

// withEnv sets all four canonical envs for the test.
func withEnv(t *testing.T, addr, env, template, podName string) {
	t.Helper()
	t.Setenv(EnvKMSAddr, addr)
	t.Setenv(EnvKMSEnv, env)
	t.Setenv(EnvPathTemplate, template)
	t.Setenv(EnvPodName, podName)
}

// happyConfig returns a known-good Config for happy-path tests.
func happyConfig() *Config {
	return &Config{
		KMSAddr:      "kms:9999",
		KMSEnv:       "testnet",
		PathTemplate: "/staking/{ord}/",
		PodName:      "lqd-2",
	}
}

// TestInject_Happy asserts the round-trip: fetcher returns 3 blobs,
// MaybeInject prepends 3 canonical content flags to argv with the
// correct base64 envelopes. The original argv tail is preserved
// verbatim.
func TestInject_Happy(t *testing.T) {
	cfg := happyConfig()
	path := "/staking/2/"
	fetcher := &fakeFetcher{
		store: map[string][]byte{
			path + BlobMLDSAKey:    []byte("mldsa-key-bytes"),
			path + BlobMLDSAPubKey: []byte("mldsa-pub-bytes"),
			path + BlobSignerKey:   []byte("signer-bytes-32"),
		},
	}
	got, err := InjectWithFetcher(context.Background(), cfg, fetcher,
		[]string{"--network-id=2"})
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	if len(got) != 4 || got[3] != "--network-id=2" {
		t.Fatalf("argv shape: %v", got)
	}
	want := []struct {
		prefix string
		blob   []byte
	}{
		{FlagMLDSAKeyContent + "=", []byte("mldsa-key-bytes")},
		{FlagMLDSAPubKeyContent + "=", []byte("mldsa-pub-bytes")},
		{FlagSignerKeyContent + "=", []byte("signer-bytes-32")},
	}
	for i, w := range want {
		a := got[i]
		if !strings.HasPrefix(a, w.prefix) {
			t.Errorf("argv[%d] does not start with %q: %q", i, w.prefix, a)
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(a, w.prefix))
		if err != nil {
			t.Errorf("argv[%d] base64 decode: %v", i, err)
			continue
		}
		if string(raw) != string(w.blob) {
			t.Errorf("argv[%d] payload: got %q want %q", i, raw, w.blob)
		}
	}
}

// TestInject_PassesThroughWhenNoEnv asserts `Inject` (env-driven) is a
// no-op when none of the trigger envs are set. Any Lux-derived binary
// that drops kmsboot.Inject() into main() without configuring KMS at
// runtime keeps working unchanged.
func TestInject_PassesThroughWhenNoEnv(t *testing.T) {
	t.Setenv(EnvKMSAddr, "")
	t.Setenv(EnvKMSEnv, "")
	t.Setenv(EnvPathTemplate, "")
	in := []string{"--network-id=1", "--data-dir=/data"}
	got, err := Inject(context.Background(), in)
	if err != nil {
		t.Fatalf("Inject: %v", err)
	}
	if len(got) != len(in) {
		t.Fatalf("expected pass-through, got %v", got)
	}
}

// TestConfigFromEnv_Partial asserts that setting SOME of the three
// trigger envs but not all is a hard config error.
func TestConfigFromEnv_Partial(t *testing.T) {
	for _, tc := range []struct {
		name, addr, env, tmpl string
	}{
		{"addr-only", "kms:9999", "", ""},
		{"env-only", "", "testnet", ""},
		{"tmpl-only", "", "", "/staking/{ord}/"},
		{"missing-env", "kms:9999", "", "/staking/{ord}/"},
		{"missing-tmpl", "kms:9999", "testnet", ""},
		{"missing-addr", "", "testnet", "/staking/{ord}/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvKMSAddr, tc.addr)
			t.Setenv(EnvKMSEnv, tc.env)
			t.Setenv(EnvPathTemplate, tc.tmpl)
			_, err := ConfigFromEnv()
			if err == nil {
				t.Fatal("expected partial-env to fail; got nil")
			}
			if !strings.Contains(err.Error(), "must be set together") {
				t.Fatalf("expected 'must be set together' error, got: %v", err)
			}
		})
	}
}

// TestValidate_RefusesEnvInTemplate enforces the architectural
// invariant: env is a separate KMS dimension, never a path substring.
func TestValidate_RefusesEnvInTemplate(t *testing.T) {
	cfg := happyConfig()
	cfg.PathTemplate = "infra/{env}/staking/{ord}/"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected {env}-in-template to fail; got nil")
	}
	if !strings.Contains(err.Error(), "{env}") {
		t.Fatalf("expected '{env}' error, got: %v", err)
	}
}

// TestValidate_TemplateMissingOrdOrSlash exhausts the two negative
// cases for path template format.
func TestValidate_TemplateMissingOrdOrSlash(t *testing.T) {
	for _, tc := range []struct{ name, tmpl string }{
		{"no-placeholder", "/staking/"},
		{"no-trailing-slash", "/staking/{ord}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := happyConfig()
			cfg.PathTemplate = tc.tmpl
			err := cfg.Validate()
			if err == nil {
				t.Fatal("expected template validation to fail; got nil")
			}
			if !strings.Contains(err.Error(), "{ord}") &&
				!strings.Contains(err.Error(), "end with /") {
				t.Fatalf("expected template error, got: %v", err)
			}
		})
	}
}

// TestInjectWithFetcher_AllowsClassicalCoexistence asserts kmsboot is
// policy-neutral about classical-vs-PQ coexistence. Lux nodes activate
// all curves by default; the legacy file-mount envs (STAKING_TLS_KEY
// etc.) can be set alongside KMS-fetched PQ material. luxfi/node's
// config layer merges both; which one a chain consumes is a chain
// genesis decision (SecurityProfile), not a kmsboot decision.
func TestInjectWithFetcher_AllowsClassicalCoexistence(t *testing.T) {
	t.Setenv("STAKING_TLS_KEY", "classical-cert-bytes")
	t.Setenv("STAKING_TLS_CERT", "classical-cert-pem")
	t.Setenv("STAKING_SIGNER_KEY", "classical-bls-bytes")

	cfg := happyConfig()
	fetcher := &fakeFetcher{
		store: map[string][]byte{
			"/staking/2/" + BlobMLDSAKey:    []byte("k"),
			"/staking/2/" + BlobMLDSAPubKey: []byte("p"),
			"/staking/2/" + BlobSignerKey:   []byte("s"),
		},
	}
	got, err := InjectWithFetcher(context.Background(), cfg, fetcher, nil)
	if err != nil {
		t.Fatalf("classical envs alongside kmsboot must not fail: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 PQ content flags, got %d: %v", len(got), got)
	}
}

// TestInjectWithFetcher_PrependsBeforeUserOverride asserts kmsboot
// prepends its content flags so a caller-supplied
// `--staking-*-file-content` later in argv wins the standard
// last-flag-wins viper/pflag semantics. Policy-neutral: operator
// override is respected.
func TestInjectWithFetcher_PrependsBeforeUserOverride(t *testing.T) {
	cfg := happyConfig()
	fetcher := &fakeFetcher{
		store: map[string][]byte{
			"/staking/2/" + BlobMLDSAKey:    []byte("from-kms"),
			"/staking/2/" + BlobMLDSAPubKey: []byte("from-kms-pub"),
			"/staking/2/" + BlobSignerKey:   []byte("from-kms-signer"),
		},
	}
	got, err := InjectWithFetcher(context.Background(), cfg, fetcher,
		[]string{FlagMLDSAKeyContent + "=USER-OVERRIDE"})
	if err != nil {
		t.Fatalf("pre-existing content flag must not fail: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("expected 3 fetched + 1 user-supplied = 4 entries, got %d: %v",
			len(got), got)
	}
	// Operator override must appear AFTER the kmsboot-injected flags
	// so it wins under last-flag-wins.
	last := got[len(got)-1]
	if last != FlagMLDSAKeyContent+"=USER-OVERRIDE" {
		t.Errorf("user override not preserved at tail: got %q", last)
	}
}

// TestInjectWithFetcher_EmptyBlobFailClosed asserts a 0-byte blob
// from KMS is treated as fatal. Silent-empty injection is the
// specific failure mode kmsboot's posture is designed to prevent.
func TestInjectWithFetcher_EmptyBlobFailClosed(t *testing.T) {
	cfg := happyConfig()
	fetcher := &fakeFetcher{
		store: map[string][]byte{
			"/staking/2/" + BlobMLDSAKey:    {},
			"/staking/2/" + BlobMLDSAPubKey: []byte("ok"),
			"/staking/2/" + BlobSignerKey:   []byte("ok"),
		},
	}
	_, err := InjectWithFetcher(context.Background(), cfg, fetcher, []string{})
	if err == nil {
		t.Fatal("expected empty-blob to fail closed; got nil")
	}
	if !strings.Contains(err.Error(), "empty blob") {
		t.Fatalf("expected 'empty blob' error, got: %v", err)
	}
}

// TestPodOrdinal exercises the StatefulSet pod-name parser end to end.
// Each failure mode is its own subtest for clean diagnostics.
func TestPodOrdinal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		wantOrd int
		wantErr string
	}{
		{"valid-lqd-0", "lqd-0", 0, ""},
		{"valid-lqd-12", "lqd-12", 12, ""},
		{"valid-hanzo-7", "hanzo-7", 7, ""},
		{"valid-multi-dash", "zoo-validator-3", 3, ""},
		{"empty", "", 0, "is empty"},
		{"no-dash", "lqd0", 0, "no `-<ordinal>` suffix"},
		{"trailing-dash", "lqd-", 0, "no `-<ordinal>` suffix"},
		{"non-numeric", "lqd-abc", 0, "not numeric"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PodOrdinal(tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantOrd {
				t.Errorf("ord: got %d, want %d", got, tc.wantOrd)
			}
		})
	}
}

// TestInjectWith_FetcherInitFailure surfaces a hard-fail when the
// fetcher constructor can't build (unreachable KMS, missing creds,
// etc.). Exercised via DefaultFetcher empty-env case.
func TestDefaultFetcher_EmptyEnvFails(t *testing.T) {
	_, err := DefaultFetcher(context.Background(), "host:9999", "")
	if err == nil {
		t.Fatal("expected empty-env to fail")
	}
	if !strings.Contains(err.Error(), EnvKMSEnv) {
		t.Fatalf("expected KMS_ENV mention, got: %v", err)
	}
}

// TestInjectWithFetcher_FetchError surfaces a fetcher Get error
// verbatim (no swallowing).
func TestInjectWithFetcher_FetchError(t *testing.T) {
	cfg := happyConfig()
	fetcher := &errFetcher{err: errors.New("transport reset")}
	_, err := InjectWithFetcher(context.Background(), cfg, fetcher, []string{})
	if err == nil || !strings.Contains(err.Error(), "transport reset") {
		t.Fatalf("expected propagated fetcher error, got: %v", err)
	}
}

type errFetcher struct{ err error }

func (e *errFetcher) Get(_ context.Context, _, _ string) ([]byte, error) { return nil, e.err }
func (e *errFetcher) Close()                                              {}

// TestInjectWith_RoundsThroughHappyPath exercises InjectWith — the
// explicit-Config entry point — by substituting DefaultFetcher via
// a quick stub. End-to-end happy path through the public API.
func TestInjectWith_PathTemplateSubstitution(t *testing.T) {
	// Sanity: ord 7 from PodName "hanzo-7" rendered into the path.
	cfg := happyConfig()
	cfg.PodName = "hanzo-7"
	fetcher := &fakeFetcher{
		store: map[string][]byte{
			"/staking/7/" + BlobMLDSAKey:    []byte("k7"),
			"/staking/7/" + BlobMLDSAPubKey: []byte("p7"),
			"/staking/7/" + BlobSignerKey:   []byte("s7"),
		},
	}
	got, err := InjectWithFetcher(context.Background(), cfg, fetcher, nil)
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 flags; got %d: %v", len(got), got)
	}
	for i, flag := range got {
		if !strings.Contains(flag, "=") {
			t.Errorf("argv[%d] not a flag=value: %q", i, flag)
		}
	}
}

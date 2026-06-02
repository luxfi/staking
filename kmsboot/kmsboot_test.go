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

// fakeFetcher returns canned bytes per (path,name). Fresh per test.
type fakeFetcher struct {
	store  map[string][]byte // key = path+name
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

// TestInject_PassThroughWhenNoAddr asserts kmsboot is a no-op when
// the trigger env KMS_ADDR is unset. Any Lux-derived binary that
// drops kmsboot.Inject() into main() without configuring KMS keeps
// working unchanged.
func TestInject_PassThroughWhenNoAddr(t *testing.T) {
	t.Setenv(EnvKMSAddr, "")
	in := []string{"--network-id=1", "--data-dir=/data"}
	got, err := Inject(context.Background(), in)
	if err != nil {
		t.Fatalf("Inject: %v", err)
	}
	if len(got) != len(in) {
		t.Fatalf("expected pass-through, got %v", got)
	}
}

// TestInjectWithFetcher_RoundTrip is the happy path. The fetcher
// returns three blobs; InjectWithFetcher prepends the three canonical
// content flags with base64-envelope of the bytes. Original argv tail
// is preserved verbatim.
func TestInjectWithFetcher_RoundTrip(t *testing.T) {
	t.Setenv(EnvPathTemplate, "/staking/{ord}/")
	t.Setenv(EnvPodName, "lqd-2")

	path := "/staking/2/"
	fetcher := &fakeFetcher{
		store: map[string][]byte{
			path + BlobMLDSAKey:    []byte("mldsa-key-bytes"),
			path + BlobMLDSAPubKey: []byte("mldsa-pub-bytes"),
			path + BlobSignerKey:   []byte("signer-bytes-32"),
		},
	}
	got, err := InjectWithFetcher(context.Background(), fetcher,
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

// TestInjectWithFetcher_PathSubstitution checks `{ord}` is replaced
// with the ordinal parsed from POD_NAME. Different pod naming
// schemes (lqd-N, hanzo-N, zoo-validator-N) all work — the suffix
// after the last `-` is what matters.
func TestInjectWithFetcher_PathSubstitution(t *testing.T) {
	for _, tc := range []struct {
		name, podName, wantPath string
	}{
		{"lqd-style", "lqd-3", "/staking/3/"},
		{"hanzo-style", "hanzo-7", "/staking/7/"},
		{"multi-dash", "zoo-validator-12", "/staking/12/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvPathTemplate, "/staking/{ord}/")
			t.Setenv(EnvPodName, tc.podName)
			fetcher := &fakeFetcher{
				store: map[string][]byte{
					tc.wantPath + BlobMLDSAKey:    []byte("k"),
					tc.wantPath + BlobMLDSAPubKey: []byte("p"),
					tc.wantPath + BlobSignerKey:   []byte("s"),
				},
			}
			if _, err := InjectWithFetcher(context.Background(), fetcher, nil); err != nil {
				t.Fatalf("inject %s: %v", tc.name, err)
			}
		})
	}
}

// TestInjectWithFetcher_PassesEmptyBytesThrough — kmsboot has zero
// opinions about what KMS returns. If the blob is empty, the flag
// gets `=` followed by base64("") = empty string. lqd's config
// layer will reject it downstream as "not PEM" or similar — that's
// the right place for that error, not here.
func TestInjectWithFetcher_PassesEmptyBytesThrough(t *testing.T) {
	t.Setenv(EnvPathTemplate, "/staking/{ord}/")
	t.Setenv(EnvPodName, "lqd-0")
	fetcher := &fakeFetcher{
		store: map[string][]byte{
			"/staking/0/" + BlobMLDSAKey:    {},
			"/staking/0/" + BlobMLDSAPubKey: []byte("ok"),
			"/staking/0/" + BlobSignerKey:   []byte("ok"),
		},
	}
	got, err := InjectWithFetcher(context.Background(), fetcher, nil)
	if err != nil {
		t.Fatalf("empty blob must not fail at the kmsboot layer: %v", err)
	}
	if got[0] != FlagMLDSAKeyContent+"=" {
		t.Errorf("expected empty payload after =, got %q", got[0])
	}
}

// TestInjectWithFetcher_FetchErrorPropagates surfaces a Fetcher.Get
// error verbatim. Bad path, transport reset, missing blob — all
// percolate up as-is.
func TestInjectWithFetcher_FetchErrorPropagates(t *testing.T) {
	t.Setenv(EnvPathTemplate, "/staking/{ord}/")
	t.Setenv(EnvPodName, "lqd-0")
	want := errors.New("transport reset")
	fetcher := &errFetcher{err: want}
	_, err := InjectWithFetcher(context.Background(), fetcher, nil)
	if err == nil || !strings.Contains(err.Error(), "transport reset") {
		t.Fatalf("expected propagated fetcher error, got: %v", err)
	}
}

type errFetcher struct{ err error }

func (e *errFetcher) Get(_ context.Context, _, _ string) ([]byte, error) { return nil, e.err }
func (e *errFetcher) Close()                                             {}

// TestPodOrdinal — keep the pod-name parser table since various Lux
// downstream binaries will name their pods differently.
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
		{"empty-returns-zero", "", 0, ""}, // empty pod name = ord 0, no error
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

// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package kmsboot fetches validator staking material from a KMS over
// native ZAP and injects it into argv as the three canonical
// `--staking-{mldsa-key,mldsa-pub-key,signer-key}-file-content` flags
// that luxfi/node's config layer (and every downstream fork)
// consumes. The bytes never touch disk — they live in argv for the
// duration of viper's config parse.
//
// kmsboot has zero opinions. It does not validate the path template,
// it does not enforce a posture, it does not refuse classical
// coexistence, it does not check blob size. If a value is set, it
// gets used. If KMS returns garbage, lqd's config layer will reject
// it downstream — that's where validation belongs, not here.
//
// Trigger: kmsboot is opt-in via the `KMS_ADDR` env var. When unset,
// `Inject` returns argv unchanged. When set, kmsboot dials and
// fetches; everything else (env, path template, pod name) is read
// from env and used as-is.
//
// # Quickstart
//
// In any Lux-based binary's main():
//
//	argv := os.Args[1:]
//	if newArgv, err := kmsboot.Inject(context.Background(), argv); err != nil {
//	    fmt.Fprintf(os.Stderr, "kmsboot: %s\n", err)
//	    os.Exit(1)
//	} else {
//	    argv = newArgv
//	}
//	// ... rest of node init
//
// # Env vars
//
//	KMS_ADDR                  KMS host:port (e.g. kms:9999).
//	                          Empty = kmsboot is a no-op.
//	KMS_ENV                   KMS env slug (used as the env dimension
//	                          of GetAt). Empty = "".
//	STAKING_KMS_PATH_TEMPLATE Per-ord path. `{ord}` is substituted
//	                          with this pod's StatefulSet ordinal.
//	                          Empty = "".
//	POD_NAME                  metadata.name; the ordinal is the suffix
//	                          after the last `-`. Empty = ordinal 0.
package kmsboot

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/luxfi/kms/pkg/zapclient"
)

// Env var names consumed by [Inject].
const (
	EnvKMSAddr      = "KMS_ADDR"
	EnvKMSEnv       = "KMS_ENV"
	EnvPathTemplate = "STAKING_KMS_PATH_TEMPLATE"
	EnvPodName      = "POD_NAME"
)

// Blob names under the per-ord path.
const (
	BlobMLDSAKey    = "mldsa.key"
	BlobMLDSAPubKey = "mldsa.pub"
	BlobSignerKey   = "signer.key"
)

// Upstream luxfi/node content-flag names. The same flags work for any
// Lux-derived binary that consumes the upstream config layer.
const (
	FlagMLDSAKeyContent    = "--staking-mldsa-key-file-content"
	FlagMLDSAPubKeyContent = "--staking-mldsa-pub-key-file-content"
	FlagSignerKeyContent   = "--staking-signer-key-file-content"
)

// Fetcher is the surface kmsboot uses to pull blobs from KMS. The
// default implementation (returned by [DefaultFetcher]) wraps
// `github.com/luxfi/kms/pkg/zapclient`; tests substitute a fake.
type Fetcher interface {
	Get(ctx context.Context, path, name string) ([]byte, error)
	Close()
}

// Inject is the entry point. Reads env vars, dials KMS, fetches the
// three blobs, prepends `--staking-*-file-content=<base64>` flags to
// argv. Returns argv unchanged when [EnvKMSAddr] is unset.
//
// All env values are used as-is — no validation, no defaulting, no
// posture enforcement. If your path template is malformed, lqd's
// config layer will complain about it after viper parses argv. That's
// the right place for that error.
func Inject(ctx context.Context, argv []string) ([]string, error) {
	addr := os.Getenv(EnvKMSAddr)
	if addr == "" {
		return argv, nil
	}
	fetcher, err := DefaultFetcher(ctx, addr, os.Getenv(EnvKMSEnv))
	if err != nil {
		return nil, fmt.Errorf("kmsboot: dial KMS %s: %w", addr, err)
	}
	defer fetcher.Close()
	return InjectWithFetcher(ctx, fetcher, argv)
}

// InjectWithFetcher does the fetch + inject given an explicit Fetcher.
// All env reads happen here (path template, pod name) so a test fake
// can run the same code path without touching the network.
func InjectWithFetcher(ctx context.Context, fetcher Fetcher, argv []string) ([]string, error) {
	ord, _ := PodOrdinal(os.Getenv(EnvPodName))
	tpl := os.Getenv(EnvPathTemplate)
	path := strings.ReplaceAll(tpl, "{ord}", strconv.Itoa(ord))

	flags := make([]string, 0, 3)
	for _, m := range []struct{ blob, flag string }{
		{BlobMLDSAKey, FlagMLDSAKeyContent},
		{BlobMLDSAPubKey, FlagMLDSAPubKeyContent},
		{BlobSignerKey, FlagSignerKeyContent},
	} {
		b, err := fetcher.Get(ctx, path, m.blob)
		if err != nil {
			return nil, fmt.Errorf("kmsboot: get %s%s: %w", path, m.blob, err)
		}
		flags = append(flags, fmt.Sprintf("%s=%s", m.flag, base64.StdEncoding.EncodeToString(b)))
	}
	return append(flags, argv...), nil
}

// DefaultFetcher dials a Liquid KMS over native ZAP at the given addr
// with the given env scope (env is bound at construction so it can't
// drift across the connection boundary).
func DefaultFetcher(ctx context.Context, addr, env string) (Fetcher, error) {
	c, err := zapclient.Dial(ctx, addr, "")
	if err != nil {
		return nil, err
	}
	return &zapFetcher{c: c, env: env}, nil
}

type zapFetcher struct {
	c   *zapclient.Client
	env string
}

func (z *zapFetcher) Get(ctx context.Context, path, name string) ([]byte, error) {
	v, err := z.c.GetAt(ctx, path, name, z.env)
	if err != nil {
		return nil, err
	}
	return []byte(v), nil
}

func (z *zapFetcher) Close() { z.c.Close() }

// PodOrdinal extracts the StatefulSet pod ordinal from a metadata.name
// like `lqd-3` (→ 3) or `hanzo-validator-12` (→ 12). The suffix after
// the LAST `-` is the ordinal. Returns (0, nil) for an empty pod
// name; returns (0, err) for a malformed suffix so callers who want
// to fail loud can.
func PodOrdinal(podName string) (int, error) {
	if podName == "" {
		return 0, nil
	}
	i := strings.LastIndex(podName, "-")
	if i < 0 || i == len(podName)-1 {
		return 0, fmt.Errorf("kmsboot: %q has no `-<ordinal>` suffix", podName)
	}
	ord, err := strconv.Atoi(podName[i+1:])
	if err != nil {
		return 0, fmt.Errorf("kmsboot: %q: ordinal suffix is not numeric: %w", podName, err)
	}
	return ord, nil
}

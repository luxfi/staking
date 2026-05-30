// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package kmsboot is the canonical boot-time staking-identity loader
// for any Lux-based validator binary. It fetches three blobs from a
// KMS service over the native ZAP transport and injects them into
// argv as the `--staking-{mldsa-key,mldsa-pub-key,signer-key}-file-
// content` flags that luxfi/node's config layer (and every downstream
// fork) already consumes. The bytes never touch disk — they live in
// argv (process memory) for the duration of viper's config parse.
//
// One in-cluster KMS, one path template, one env slug. Each validator
// pod resolves its own StatefulSet ordinal from `POD_NAME` and pulls
// its own bundle. No K8s Secret, no per-pod file mount.
//
// # Policy-neutral
//
// kmsboot fetches and injects — nothing else. It does not enforce
// strict-PQ posture, classical-vs-PQ exclusivity, or any other
// posture choice. Lux nodes activate all curves and crypto
// precompiles by default; whether a given chain consumes the
// classical secp256k1 NodeID or the strict-PQ ML-DSA NodeID is a
// chain-config decision (genesis `SecurityProfile`, upgrade-config
// flags) made elsewhere. Classical staking material (mounted from a
// K8s Secret as `STAKING_TLS_KEY`/`STAKING_TLS_CERT`/
// `STAKING_SIGNER_KEY`) can coexist freely with the PQ material
// kmsboot fetches. luxfi/node's config layer merges both.
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
// `Inject` is a no-op (returns argv unchanged) when none of the three
// trigger envs (`KMS_ADDR`, `KMS_ENV`, `STAKING_KMS_PATH_TEMPLATE`)
// are set.
//
// # Addressing
//
// Canonical KMS native:
//
//	Addr — KMS_ADDR  (host:port; e.g. kms:9999)
//	Env  — KMS_ENV   (env slug; orthogonal dimension carried at the
//	                  GetAt/PutAt boundary)
//	Path — STAKING_KMS_PATH_TEMPLATE (must contain `{ord}`, must end
//	                  with `/`, MUST NOT contain `{env}`)
//	Name — mldsa.key | mldsa.pub | signer.key
//
// env is NEVER embedded in the path. Conflating location with scope
// is what makes cross-env isolation a string-substitution convention
// rather than a property of the KMS access boundary.
//
// # Correctness checks (always on)
//
// kmsboot enforces a minimum set of correctness invariants. These are
// architectural, not policy:
//
//   - All three trigger envs must be set together. Partial = hard fail.
//   - `{env}` in the path template = hard fail (env is a separate KMS
//     dimension, not a path substring).
//   - Path template must contain `{ord}` and end with `/` = hard fail.
//   - Empty blob from KMS = hard fail (no silent partial registration).
//
// # Test seam
//
// `InjectWithFetcher` accepts an explicit `Fetcher` so tests can
// substitute a fake. The default `Fetcher` (returned by
// `DefaultFetcher`) wraps `github.com/luxfi/kms/pkg/zapclient`.
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

// Canonical env vars consumed by [ConfigFromEnv] and [Inject].
const (
	EnvKMSAddr      = "KMS_ADDR"
	EnvKMSEnv       = "KMS_ENV"
	EnvPathTemplate = "STAKING_KMS_PATH_TEMPLATE"
	EnvPodName      = "POD_NAME"
)

// blob names under the canonical per-ord path. Order matters only for
// log output; the three are fetched in this order.
const (
	BlobMLDSAKey    = "mldsa.key"
	BlobMLDSAPubKey = "mldsa.pub"
	BlobSignerKey   = "signer.key"
)

// upstream luxfi/node content-flag names. The same flags work for any
// Lux-derived binary that consumes the upstream config layer.
const (
	FlagMLDSAKeyContent    = "--staking-mldsa-key-file-content"
	FlagMLDSAPubKeyContent = "--staking-mldsa-pub-key-file-content"
	FlagSignerKeyContent   = "--staking-signer-key-file-content"
)

// Config drives one boot-time identity load.
type Config struct {
	// KMSAddr is the KMS endpoint (host:port). Required.
	KMSAddr string

	// KMSEnv is the KMS env slug — the orthogonal dimension carried at
	// every GetAt/PutAt. e.g. "mainnet", "testnet", "devnet". Required.
	KMSEnv string

	// PathTemplate is the per-ord blob path. MUST contain `{ord}`,
	// MUST end with `/`, and MUST NOT contain `{env}` (env is the
	// separate KMS dimension above). Required.
	//
	// Example: `/staking/{ord}/`
	PathTemplate string

	// PodName is the K8s-injected metadata.name (e.g. `lqd-3`,
	// `hanzo-2`). The ordinal is the suffix after the last `-`.
	// Required at Inject time; not validated by Validate() since a
	// programmatic caller may know the ord by other means and bypass
	// the env-var path (see [InjectWith]).
	PodName string
}

// Validate enforces the architectural correctness invariants on the
// static fields of Config — not posture. (PodName is checked at
// Inject time because programmatic callers might supply the ordinal
// directly via [InjectWith] without setting PodName.)
func (c *Config) Validate() error {
	if c.KMSAddr == "" {
		return fmt.Errorf("kmsboot: %s is required", EnvKMSAddr)
	}
	if c.KMSEnv == "" {
		return fmt.Errorf("kmsboot: %s is required", EnvKMSEnv)
	}
	if c.PathTemplate == "" {
		return fmt.Errorf("kmsboot: %s is required", EnvPathTemplate)
	}
	if !strings.Contains(c.PathTemplate, "{ord}") || !strings.HasSuffix(c.PathTemplate, "/") {
		return fmt.Errorf(
			"kmsboot: %s must contain `{ord}` placeholder AND end with /: %q",
			EnvPathTemplate, c.PathTemplate)
	}
	if strings.Contains(c.PathTemplate, "{env}") {
		return fmt.Errorf(
			"kmsboot: %s must NOT contain `{env}` — env is a separate KMS dimension "+
				"carried by %s, not a path substring: %q",
			EnvPathTemplate, EnvKMSEnv, c.PathTemplate)
	}
	return nil
}

// ConfigFromEnv loads a Config from the canonical env vars. Returns
// `(nil, nil)` when NONE of the three trigger envs are set — the
// kmsboot path is opt-in and a binary without any of them carries on
// with its normal (classical-compat or no-op) staking path. Returns
// an error when SOME are set but not all — strict-PQ refuses to guess.
func ConfigFromEnv() (*Config, error) {
	addr := os.Getenv(EnvKMSAddr)
	env := os.Getenv(EnvKMSEnv)
	tpl := os.Getenv(EnvPathTemplate)
	if addr == "" && env == "" && tpl == "" {
		return nil, nil
	}
	if addr == "" || env == "" || tpl == "" {
		return nil, fmt.Errorf(
			"kmsboot: %s, %s, and %s must be set together "+
				"(have %s=%q, %s=%q, %s=%q)",
			EnvKMSAddr, EnvKMSEnv, EnvPathTemplate,
			EnvKMSAddr, addr, EnvKMSEnv, env, EnvPathTemplate, tpl)
	}
	cfg := &Config{
		KMSAddr:      addr,
		KMSEnv:       env,
		PathTemplate: tpl,
		PodName:      os.Getenv(EnvPodName),
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Fetcher is the surface Inject uses to pull blobs from KMS. The
// default implementation (returned by [DefaultFetcher]) wraps
// `github.com/luxfi/kms/pkg/zapclient`; tests substitute a fake.
type Fetcher interface {
	// Get fetches `name` at `path`. Empty bytes with nil error is
	// treated by Inject as a hard fail (no silent empty key).
	Get(ctx context.Context, path, name string) ([]byte, error)
	// Close releases the underlying transport. Idempotent.
	Close()
}

// DefaultFetcher dials a Liquid KMS over native ZAP at the given addr
// with the given env scope. The hybrid X25519 + ML-KEM-768 handshake
// runs during Dial; each Get is sealed under the resulting session.
//
// `env` is bound at construction so a stray flag cannot bleed across
// the connection boundary.
func DefaultFetcher(ctx context.Context, addr, env string) (Fetcher, error) {
	if env == "" {
		return nil, fmt.Errorf("kmsboot: %s is required (env-scoped GetAt)", EnvKMSEnv)
	}
	c, err := zapclient.Dial(ctx, addr, "")
	if err != nil {
		return nil, fmt.Errorf("kmsboot: dial KMS %s: %w", addr, err)
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

// Inject is the env-driven convenience. Reads a Config from env vars
// via [ConfigFromEnv], dials a default fetcher, fetches the three
// blobs, prepends the three content flags to argv, returns the
// extended argv. Returns argv unchanged when no kmsboot config is
// present.
//
// This is the entry point any Lux-based main() should use:
//
//	argv := os.Args[1:]
//	if newArgv, err := kmsboot.Inject(ctx, argv); err != nil {
//	    fmt.Fprintf(os.Stderr, "kmsboot: %s\n", err)
//	    os.Exit(1)
//	} else {
//	    argv = newArgv
//	}
func Inject(ctx context.Context, argv []string) ([]string, error) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return argv, nil
	}
	return InjectWith(ctx, cfg, argv)
}

// InjectWith uses an explicit Config (env-var bypass for programmatic
// callers). Dials a default fetcher.
func InjectWith(ctx context.Context, cfg *Config, argv []string) ([]string, error) {
	fetcher, err := DefaultFetcher(ctx, cfg.KMSAddr, cfg.KMSEnv)
	if err != nil {
		return nil, fmt.Errorf("kmsboot: init fetcher: %w", err)
	}
	defer fetcher.Close()
	return InjectWithFetcher(ctx, cfg, fetcher, argv)
}

// InjectWithFetcher does the work given an explicit Fetcher. All
// posture checks run here (regardless of which higher-level entry
// point was used). Suitable for tests and for callers wrapping a
// non-default KMS transport.
func InjectWithFetcher(
	ctx context.Context, cfg *Config, fetcher Fetcher, argv []string,
) ([]string, error) {
	if cfg == nil {
		return nil, fmt.Errorf("kmsboot: Config is nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	ord, err := podOrdinal(cfg.PodName)
	if err != nil {
		return nil, err
	}
	path := strings.ReplaceAll(cfg.PathTemplate, "{ord}", strconv.Itoa(ord))

	mldsaKey, err := fetchFlag(ctx, fetcher, path, BlobMLDSAKey, FlagMLDSAKeyContent)
	if err != nil {
		return nil, err
	}
	mldsaPub, err := fetchFlag(ctx, fetcher, path, BlobMLDSAPubKey, FlagMLDSAPubKeyContent)
	if err != nil {
		return nil, err
	}
	signer, err := fetchFlag(ctx, fetcher, path, BlobSignerKey, FlagSignerKeyContent)
	if err != nil {
		return nil, err
	}

	// Prepend so a caller-supplied `--staking-*-file-content` later in
	// argv would win the standard `last-flag-wins` viper/pflag semantics.
	// kmsboot is policy-neutral: if the operator wants their override
	// to take precedence over the KMS-fetched bytes, we let it.
	return append([]string{mldsaKey, mldsaPub, signer}, argv...), nil
}

// fetchFlag fetches `<path><name>` and returns `--flag=<base64(bytes)>`.
// Empty bytes are a hard fail (silent-empty injection is the specific
// failure mode this package was designed to prevent).
func fetchFlag(
	ctx context.Context, f Fetcher, path, name, flag string,
) (string, error) {
	b, err := f.Get(ctx, path, name)
	if err != nil {
		return "", fmt.Errorf("kmsboot: fetch %s%s: %w", path, name, err)
	}
	if len(b) == 0 {
		return "", fmt.Errorf("kmsboot: empty blob at %s%s (fail closed)", path, name)
	}
	return fmt.Sprintf("%s=%s", flag, base64.StdEncoding.EncodeToString(b)), nil
}

// PodOrdinal extracts the StatefulSet pod ordinal from a metadata.name
// like `lqd-3` (→ 3) or `hanzo-12` (→ 12). The convention is K8s
// StatefulSet's: the suffix after the LAST `-` is the ordinal. A
// missing or non-numeric suffix is a fatal config error — refusing to
// guess is the strict-PQ posture.
//
// Exposed so a caller can derive the ordinal themselves and pass it
// through Config.PodName before calling [InjectWith].
func PodOrdinal(podName string) (int, error) { return podOrdinal(podName) }

func podOrdinal(podName string) (int, error) {
	if podName == "" {
		return 0, fmt.Errorf(
			"kmsboot: %s is empty; set valueFrom.fieldRef.fieldPath=metadata.name "+
				"on the validator container env (the operator does this when "+
				"%s is set on the CR)", EnvPodName, EnvPathTemplate)
	}
	i := strings.LastIndex(podName, "-")
	if i < 0 || i == len(podName)-1 {
		return 0, fmt.Errorf("kmsboot: %s %q has no `-<ordinal>` suffix", EnvPodName, podName)
	}
	ord, err := strconv.Atoi(podName[i+1:])
	if err != nil {
		return 0, fmt.Errorf("kmsboot: %s %q: ordinal suffix is not numeric: %w",
			EnvPodName, podName, err)
	}
	if ord < 0 {
		return 0, fmt.Errorf("kmsboot: %s %q: ordinal must be >= 0, got %d",
			EnvPodName, podName, ord)
	}
	return ord, nil
}

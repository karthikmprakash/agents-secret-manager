// Package resolve turns the manifest, .env files and the process environment
// into the child environment for `sm exec`.
//
// Precedence (lowest to highest): .env, .env.<profile>, .env.local, process
// env. Manifest-declared secrets with transport env/generated are injected
// from the vault under their own name; .env values of the form sm://NAME bind
// an env var to a declared secret. A differing plaintext value for a managed
// name refuses to run unless SM_ALLOW_PLAINTEXT=1; empty and identical values
// are allowed (identical values keep nested `sm exec` calls working).
package resolve

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
)

// Getter is the subset of store.Store that resolution needs.
type Getter interface {
	Get(key string) (value string, found bool, err error)
}

// Options controls resolution.
type Options struct {
	// Profile loads .env.<profile> between .env and .env.local.
	Profile string
	// AllowPlaintext lets a plaintext value override a vault-managed name.
	AllowPlaintext bool
	// Environ overrides the process environment (tests). nil → os.Environ().
	Environ []string
}

// Result is the resolved child environment.
type Result struct {
	Env       []string // KEY=VALUE pairs, sorted
	Injected  []string // manifest secret names injected (sorted)
	DotenvRef []string // env vars bound via sm:// refs (sorted)
	Files     []string // .env files read, lowest precedence first
	FromFiles int      // vars sourced from .env files
	Warnings  []string
}

type layer struct {
	source string
	vars   Dotenv
}

type decl struct {
	value  string
	ref    bool
	source string
}

// Build resolves the child environment for the project that loaded describes.
// projectDir is where the .env files live (the manifest's directory).
func Build(loaded *manifest.Loaded, st Getter, projectDir string, opts Options) (*Result, error) {
	res := &Result{}

	files, err := loadChain(projectDir, opts.Profile)
	if err != nil {
		return nil, err
	}

	layers := make([]layer, 0, len(files)+1)
	for _, f := range files {
		res.Files = append(res.Files, f.path)
		layers = append(layers, layer{source: f.path, vars: f.vars})
	}

	environ := opts.Environ
	if environ == nil {
		environ = os.Environ()
	}
	parent := map[string]string{}
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && k != "" {
			parent[k] = v
		}
	}
	layers = append(layers, layer{source: "process env", vars: parent})

	// Effective declaration per var: highest precedence wins. Track lower
	// precedence sm:// declarations that end up shadowed by plaintext.
	effective := map[string]decl{}
	shadowedRef := map[string]decl{}
	for i := len(layers) - 1; i >= 0; i-- {
		for k, v := range layers[i].vars {
			if d, seen := effective[k]; seen {
				if !d.ref && isRef(v) {
					if _, recorded := shadowedRef[k]; !recorded {
						shadowedRef[k] = decl{value: v, ref: true, source: layers[i].source}
					}
				}
				continue
			}
			effective[k] = decl{value: v, ref: isRef(v), source: layers[i].source}
		}
	}

	merged := loaded.Merged()

	// Manifest-declared env secrets are injected under their own name.
	manifestBindings := map[string]string{}
	for name, s := range merged.Secrets {
		switch s.Transport {
		case manifest.TransportEnv, manifest.TransportGen:
			manifestBindings[name] = name
		}
	}

	// .env sm:// refs bind an env var to a declared secret.
	refBindings := map[string]string{}
	for k, d := range effective {
		if !d.ref {
			continue
		}
		logical := strings.TrimPrefix(d.value, "sm://")
		if logical == "" {
			return nil, fmt.Errorf("%s: %s has an empty sm:// reference", d.source, k)
		}
		s, ok := merged.Secrets[logical]
		if !ok {
			return nil, fmt.Errorf("%s: %s references sm://%s, but no [secrets.%s] is declared", d.source, k, logical, logical)
		}
		switch s.Transport {
		case manifest.TransportProxy:
			return nil, fmt.Errorf("secret %s: transport \"proxy\" cannot be injected as env (v0.3 broker)", logical)
		case manifest.TransportFile:
			return nil, fmt.Errorf("secret %s: transport \"file\" cannot be injected as env — use sm inject --tpl (M5)", logical)
		}
		if existing, ok := manifestBindings[k]; ok {
			if existing != logical {
				return nil, fmt.Errorf("env var %s is bound to both %s (manifest) and %s (.env)", k, existing, logical)
			}
			continue
		}
		refBindings[k] = logical
	}

	bindings := map[string]string{}
	for k, v := range manifestBindings {
		bindings[k] = v
	}
	for k, v := range refBindings {
		bindings[k] = v
	}

	// Fetch values from the store.
	values := map[string]string{}
	for envName, secretName := range bindings {
		s := merged.Secrets[secretName]
		ref, err := manifest.ParseRef(s.Ref)
		if err != nil {
			return nil, fmt.Errorf("secret %s: %w", secretName, err)
		}
		val, found, err := st.Get(ref.Path)
		if err != nil {
			return nil, fmt.Errorf("secret %s: %w", secretName, err)
		}
		if !found {
			return nil, fmt.Errorf("secret %s is declared but missing from the vault (%s)", secretName, s.Ref)
		}
		values[envName] = val
	}

	// Refuse plaintext shadows of vault-managed names.
	for envName, vaultVal := range values {
		d, ok := effective[envName]
		if !ok || d.ref || d.value == "" || d.value == vaultVal {
			continue
		}
		if opts.AllowPlaintext {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("%s: plaintext from %s overrides the vault (SM_ALLOW_PLAINTEXT=1)", envName, d.source))
			values[envName] = d.value
			continue
		}
		return nil, fmt.Errorf("%s is set in plaintext (%s) but managed by the vault — remove it, or set SM_ALLOW_PLAINTEXT=1 to use the plaintext value", envName, d.source)
	}

	// Assemble the child env: plaintext effective vars + vault values.
	envMap := map[string]string{}
	fromFiles := 0
	for k, d := range effective {
		if d.ref {
			continue
		}
		if _, managed := values[k]; managed {
			continue
		}
		envMap[k] = d.value
		if d.source != "process env" {
			fromFiles++
		}
	}
	for k, v := range values {
		envMap[k] = v
	}
	res.FromFiles = fromFiles

	keys := make([]string, 0, len(envMap))
	for k := range envMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	res.Env = make([]string, 0, len(keys))
	for _, k := range keys {
		res.Env = append(res.Env, k+"="+envMap[k])
	}

	for k := range manifestBindings {
		res.Injected = append(res.Injected, k)
	}
	sort.Strings(res.Injected)
	for k := range refBindings {
		res.DotenvRef = append(res.DotenvRef, k)
	}
	sort.Strings(res.DotenvRef)

	// Warn about sm:// declarations beaten by higher-precedence plaintext.
	var shadowKeys []string
	for k := range shadowedRef {
		shadowKeys = append(shadowKeys, k)
	}
	sort.Strings(shadowKeys)
	for _, k := range shadowKeys {
		d := effective[k]
		if d.ref {
			continue
		}
		if _, managed := values[k]; managed {
			continue // already reported by the shadow check
		}
		lower := shadowedRef[k]
		// Suppress when the plaintext equals what the ref would resolve to —
		// e.g. a nested sm exec injected the same value into the parent env.
		if sameAsRefValue(merged, st, lower.value, d.value) {
			continue
		}
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("%s: plaintext from %s overrides an sm:// declaration from %s", k, d.source, lower.source))
	}

	return res, nil
}

// sameAsRefValue reports whether plain equals the vault value behind refValue.
func sameAsRefValue(merged *manifest.Manifest, st Getter, refValue, plain string) bool {
	logical := strings.TrimPrefix(refValue, "sm://")
	s, ok := merged.Secrets[logical]
	if !ok {
		return false
	}
	ref, err := manifest.ParseRef(s.Ref)
	if err != nil {
		return false
	}
	val, found, err := st.Get(ref.Path)
	if err != nil || !found {
		return false
	}
	return val == plain
}

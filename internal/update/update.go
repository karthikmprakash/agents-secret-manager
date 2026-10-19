// Package update checks the latest published GitHub release. It is called only
// by an explicit user action; nothing here runs in the background.
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/karthikmprakash/agents-secret-manager/internal/config"
	"github.com/karthikmprakash/agents-secret-manager/internal/safeio"
)

const cacheName = "update.json"

// apiURL is a variable so tests can point at an httptest server.
var apiURL = "https://api.github.com/repos/karthikmprakash/agents-secret-manager/releases/latest"

// Result describes the latest published release relative to the running build.
type Result struct {
	Current   string    `json:"current"`
	Latest    string    `json:"latest"`
	URL       string    `json:"url,omitempty"`
	Available bool      `json:"available"`
	CheckedAt time.Time `json:"checkedAt"`
}

type release struct {
	Tag       string `json:"tag_name"`
	URL       string `json:"html_url"`
	Published string `json:"published_at"`
}

type cacheFile struct {
	Latest    string    `json:"latest"`
	URL       string    `json:"url"`
	CheckedAt time.Time `json:"checked_at"`
}

// Check fetches the latest release and writes a local cache entry. It is an
// explicit network action; callers should make that clear in their UI.
func Check(ctx context.Context, current string) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "sm/"+current)
	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("update check failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("update check failed: GitHub returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Result{}, err
	}
	var rel release
	if err := json.Unmarshal(data, &rel); err != nil {
		return Result{}, fmt.Errorf("update check returned an unexpected response")
	}
	latest := strings.TrimPrefix(strings.TrimSpace(rel.Tag), "v")
	if latest == "" {
		return Result{}, fmt.Errorf("update check returned no release tag")
	}
	result := Result{
		Current:   current,
		Latest:    latest,
		URL:       rel.URL,
		Available: Compare(latest, current) > 0,
		CheckedAt: time.Now().UTC(),
	}
	if err := writeCache(cacheFile{Latest: result.Latest, URL: result.URL, CheckedAt: result.CheckedAt}); err == nil {
		// A cache failure must not invalidate a successful check.
	}
	return result, nil
}

// Cached returns the last check without making a network request.
func Cached(current string) (Result, bool) {
	path, err := cachePath()
	if err != nil {
		return Result{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{}, false
	}
	var c cacheFile
	if err := json.Unmarshal(data, &c); err != nil || c.Latest == "" {
		return Result{}, false
	}
	return Result{
		Current:   current,
		Latest:    c.Latest,
		URL:       c.URL,
		Available: Compare(c.Latest, current) > 0,
		CheckedAt: c.CheckedAt,
	}, true
}

func cachePath() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, cacheName), nil
}

func writeCache(c cacheFile) error {
	path, err := cachePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return safeio.Write(path, append(data, '\n'), 0o600)
}

// Compare compares semantic-ish versions. A release is newer than its
// prerelease; numeric identifiers compare numerically. It returns -1, 0 or 1.
func Compare(a, b string) int {
	a, b = strings.TrimPrefix(a, "v"), strings.TrimPrefix(b, "v")
	if a == b {
		return 0
	}
	ac, ap := splitVersion(a)
	bc, bp := splitVersion(b)
	for i := 0; i < 3; i++ {
		if ac[i] != bc[i] {
			if ac[i] < bc[i] {
				return -1
			}
			return 1
		}
	}
	// A release (no prerelease) is newer than any prerelease with the same core.
	if ap == "" && bp != "" {
		return 1
	}
	if ap != "" && bp == "" {
		return -1
	}
	return comparePrerelease(ap, bp)
}

func splitVersion(v string) ([3]int, string) {
	core, pre, _ := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	var nums [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		n, _ := strconv.Atoi(strings.TrimSpace(parts[i]))
		nums[i] = n
	}
	return nums, pre
}

func comparePrerelease(a, b string) int {
	if a == b {
		return 0
	}
	ap, bp := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(ap) && i < len(bp); i++ {
		if ap[i] == bp[i] {
			continue
		}
		an, aerr := strconv.Atoi(ap[i])
		bn, berr := strconv.Atoi(bp[i])
		switch {
		case aerr == nil && berr == nil:
			if an < bn {
				return -1
			}
			return 1
		case aerr == nil:
			return -1 // numeric identifiers sort before alphanumeric
		case berr == nil:
			return 1
		default:
			if ap[i] < bp[i] {
				return -1
			}
			return 1
		}
	}
	if len(ap) < len(bp) {
		return -1
	}
	if len(ap) > len(bp) {
		return 1
	}
	return 0
}

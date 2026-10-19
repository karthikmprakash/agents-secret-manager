// Package uiserver serves the embedded desktop UI on authenticated loopback.
package uiserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/karthikmprakash/agents-secret-manager/internal/audit"
	"github.com/karthikmprakash/agents-secret-manager/internal/config"
	"github.com/karthikmprakash/agents-secret-manager/internal/detect"
	"github.com/karthikmprakash/agents-secret-manager/internal/generate"
	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/resolve"
	"github.com/karthikmprakash/agents-secret-manager/internal/scan"
	"github.com/karthikmprakash/agents-secret-manager/internal/secrets"
	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
	"github.com/karthikmprakash/agents-secret-manager/internal/update"
	"github.com/karthikmprakash/agents-secret-manager/internal/wireup"
)

// BuildVersion is set by the CLI before starting the UI. The update check is
// explicit; this value is only used for comparison and the User-Agent.
var BuildVersion = "dev"

//go:embed ui/index.html
var uiFS embed.FS

type Server struct {
	http                     *http.Server
	URL                      string
	token, host, cookie, csp string
}

func Start(port int) (*Server, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	s := &Server{token: hex.EncodeToString(b), host: ln.Addr().String()}
	s.cookie = fmt.Sprintf("sm_session_%d", ln.Addr().(*net.TCPAddr).Port)
	s.URL = "http://" + s.host + "/?token=" + s.token
	page, _ := uiFS.ReadFile("ui/index.html")
	s.csp = "default-src 'none'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; script-src " + inlineHash(page, "script") + "; style-src 'unsafe-inline'"
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.auth(s.index))
	mux.HandleFunc("GET /api/state", s.auth(s.state))
	mux.HandleFunc("POST /api/reveal", s.auth(s.reveal))
	mux.HandleFunc("POST /api/update/check", s.auth(s.checkUpdate))
	mux.HandleFunc("POST /api/initialize", s.auth(s.initialize))
	mux.HandleFunc("POST /api/add", s.auth(s.add))
	mux.HandleFunc("POST /api/group", s.auth(s.group))
	mux.HandleFunc("POST /api/service", s.auth(s.service))
	mux.HandleFunc("POST /api/recovery/export", s.auth(s.exportRecovery))
	mux.HandleFunc("POST /api/recovery/inspect", s.auth(s.inspectRecovery))
	mux.HandleFunc("POST /api/recovery/restore", s.auth(s.restoreRecovery))
	mux.HandleFunc("POST /api/rotate", s.auth(s.rotate))
	mux.HandleFunc("POST /api/import", s.auth(s.bulkImport))
	mux.HandleFunc("POST /api/detect", s.auth(s.detect))
	mux.HandleFunc("POST /api/review-detected", s.auth(s.reviewDetected))
	mux.HandleFunc("POST /api/add-detected", s.auth(s.addDetected))
	mux.HandleFunc("GET /api/agents", s.auth(s.agents))
	mux.HandleFunc("GET /api/mcp-config", s.auth(s.mcpConfig))
	mux.HandleFunc("POST /api/setup", s.auth(s.setup))
	mux.HandleFunc("POST /api/doctor", s.auth(s.doctor))
	s.http = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	go func() { _ = s.http.Serve(ln) }()
	return s, nil
}

func inlineHash(page []byte, tag string) string {
	start := bytes.Index(page, []byte("<"+tag+">"))
	if start < 0 {
		return "'none'"
	}
	start += len(tag) + 2
	end := bytes.Index(page[start:], []byte("</"+tag+">"))
	if end < 0 {
		return "'none'"
	}
	sum := sha256.Sum256(page[start : start+end])
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

func (s *Server) Close() error { return s.http.Close() }
func (s *Server) matches(token string) bool {
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) == 1
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", s.csp)
		if r.Host != s.host {
			http.Error(w, "invalid host", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+s.host {
			http.Error(w, "cross-origin request denied", http.StatusForbidden)
			return
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "cross-site request denied", http.StatusForbidden)
			return
		}
		authorization := r.Header.Get("Authorization")
		ok := strings.HasPrefix(authorization, "Bearer ") && s.matches(strings.TrimPrefix(authorization, "Bearer "))
		if c, err := r.Cookie(s.cookie); err == nil {
			ok = ok || s.matches(c.Value)
		}
		// Query tokens only bootstrap the document, never mutation endpoints.
		if r.Method == "GET" && r.URL.Path == "/" && s.matches(r.URL.Query().Get("token")) {
			ok = true
			http.SetCookie(w, &http.Cookie{Name: s.cookie, Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		}
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if r.Method == "POST" && mediaType != "application/json" {
			writeError(w, 415, fmt.Errorf("use application/json"))
			return
		}
		next(w, r)
	}
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	page, _ := uiFS.ReadFile("ui/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(page)
}

type secretView struct {
	Name      string `json:"name"`
	Scope     string `json:"scope"`
	Transport string `json:"transport"`
	Ref       string `json:"ref"`
	Status    string `json:"status"`
	Service   string `json:"service,omitempty"`
	Sensitive bool   `json:"sensitive"`
	// Preview is the full value for plain config entries, or a last-four hint
	// for sensitive values. The full sensitive value is only returned by
	// /api/reveal after an explicit local action.
	Preview    string `json:"preview,omitempty"`
	Revealable bool   `json:"revealable,omitempty"`
}
type auditView struct {
	TS      string   `json:"ts"`
	Action  string   `json:"action"`
	Secrets []string `json:"secrets"`
	Cmd     string   `json:"cmd"`
}
type stateResponse struct {
	Vault           string         `json:"vault"`
	GlobalManifest  string         `json:"globalManifest"`
	ProjectManifest string         `json:"projectManifest"`
	ProjectName     string         `json:"projectName"`
	Initialized     bool           `json:"initialized"`
	VaultError      string         `json:"vaultError,omitempty"`
	AuditError      string         `json:"auditError,omitempty"`
	Secrets         []secretView   `json:"secrets"`
	Audit           []auditView    `json:"audit"`
	Update          *update.Result `json:"update,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
func decode(r *http.Request, v any) error {
	return decodeLimit(r, v, 1<<20)
}

func decodeLimit(r *http.Request, v any, limit int64) error {
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || int64(len(data)) > limit {
		return fmt.Errorf("request exceeds the size limit or could not be read")
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return fmt.Errorf("request must contain a JSON object")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("invalid request body")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("request must contain one JSON object")
	}
	return nil
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	cwd, err := os.Getwd()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	l, err := manifest.LoadOptional(cwd)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	resp := stateResponse{GlobalManifest: l.GlobalPath, ProjectManifest: l.ProjectPath, ProjectName: l.Merged().Project.Name, Secrets: []secretView{}, Audit: []auditView{}}
	vp, err := keys.VaultPath()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	resp.Vault = vp
	var v *vaultfile.Vault
	id, err := keys.Get()
	if err == nil {
		v, err = vaultfile.Open(vp, id)
		if err == nil {
			_, err = os.Stat(vp)
			resp.Initialized = err == nil
		}
	}
	if err != nil && !errors.Is(err, keys.ErrNotFound) && !os.IsNotExist(err) {
		resp.VaultError = "Vault unavailable. Unlock your Keychain or restore the correct identity and vault."
	}
	if errors.Is(err, keys.ErrNotFound) {
		if _, e := os.Stat(vp); e == nil {
			resp.VaultError = "Vault exists but its Keychain identity is missing. Restore it before continuing."
		}
	}
	for name, sec := range l.Merged().Secrets {
		scope := "global"
		if l.Project != nil {
			if _, ok := l.Project.Secrets[name]; ok {
				scope = "project"
			}
		}
		status := "unavailable"
		preview := ""
		revealable := false
		if v != nil {
			ref, _ := manifest.ParseRef(sec.Ref)
			stored, found, _ := v.Get(ref.Path)
			status = "missing"
			if found {
				status = "present"
				if sec.IsSensitive() {
					preview = maskHint(stored)
					revealable = true
				} else {
					preview = stored
				}
			}
		}
		resp.Secrets = append(resp.Secrets, secretView{
			Name: name, Scope: scope, Transport: sec.Transport, Ref: sec.Ref,
			Status: status, Service: sec.Service, Sensitive: sec.IsSensitive(),
			Preview: preview, Revealable: revealable,
		})
	}
	sort.Slice(resp.Secrets, func(i, j int) bool { return resp.Secrets[i].Name < resp.Secrets[j].Name })
	dir, err := config.Dir()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	entries, err := audit.Read(dir)
	if err != nil {
		resp.AuditError = "Audit log could not be read; run sm log verify."
	} else {
		for i := len(entries) - 1; i >= 0 && len(resp.Audit) < 50; i-- {
			e := entries[i]
			resp.Audit = append(resp.Audit, auditView{e.TS, e.Action, e.Secrets, e.Cmd})
		}
	}
	if cached, ok := update.Cached(BuildVersion); ok {
		resp.Update = &cached
	}
	writeJSON(w, 200, resp)
}

// checkUpdate is the only endpoint that contacts GitHub. The UI calls it from
// the explicit update button; the dashboard never checks in the background.
func (s *Server) checkUpdate(w http.ResponseWriter, r *http.Request) {
	var body struct{}
	if err := decode(r, &body); err != nil {
		writeError(w, 400, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	result, err := update.Check(ctx, BuildVersion)
	if err != nil {
		writeError(w, 502, err)
		return
	}
	writeJSON(w, 200, result)
}

// maskHint keeps the last four characters of a sensitive value so the owner can
// recognize it without putting the whole value on screen.
func maskHint(value string) string {
	runes := []rune(value)
	if len(runes) < 8 {
		return "••••"
	}
	return "••••" + string(runes[len(runes)-4:])
}

type revealRequest struct {
	Name  string `json:"name"`
	Scope string `json:"scope,omitempty"`
}

// reveal returns one value to the authenticated local UI and records the
// action. It is intentionally not exposed over MCP.
func (s *Server) reveal(w http.ResponseWriter, r *http.Request) {
	var req revealRequest
	if err := decode(r, &req); err != nil {
		writeError(w, 400, err)
		return
	}
	if !manifest.ValidName(req.Name) {
		writeError(w, 400, fmt.Errorf("invalid secret name"))
		return
	}
	cwd, err := os.Getwd()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	loaded, err := manifest.LoadOptional(cwd)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	merged := loaded.Merged()
	secret, ok := merged.Secrets[req.Name]
	if !ok {
		writeError(w, 404, fmt.Errorf("%s is not declared", req.Name))
		return
	}
	if req.Scope == "global" && loaded.Project != nil {
		if _, projectOwns := loaded.Project.Secrets[req.Name]; projectOwns {
			if global, ok := loaded.Global.Secrets[req.Name]; ok {
				secret = global
			}
		}
	}
	ref, err := manifest.ParseRef(secret.Ref)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	identity, err := keys.Get()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	vaultPath, err := keys.VaultPath()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	v, err := vaultfile.Open(vaultPath, identity)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	value, found, err := v.Get(ref.Path)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	if !found {
		writeError(w, 404, fmt.Errorf("%s has no stored value", req.Name))
		return
	}
	if dir, err := config.Dir(); err == nil {
		_ = audit.Append(dir, audit.Entry{
			TS:      time.Now().UTC().Format(time.RFC3339),
			Session: audit.NewSession(),
			Action:  "reveal",
			Secrets: []string{req.Name},
			Cmd:     "sm ui reveal",
			CWD:     cwd,
		})
	}
	writeJSON(w, 200, map[string]any{
		"name":      req.Name,
		"value":     value,
		"sensitive": secret.IsSensitive(),
	})
}

func (s *Server) initialize(w http.ResponseWriter, r *http.Request) {
	var body struct{}
	if err := decode(r, &body); err != nil {
		writeError(w, 400, err)
		return
	}
	if err := secrets.Initialize(); err != nil {
		writeError(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

type addRequest struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Scope     string `json:"scope"`
	Transport string `json:"transport"`
	Generate  string `json:"generate"`
	Service   string `json:"service"`
	Sensitive *bool  `json:"sensitive"`
}

func target(scope string) (string, error) {
	if scope == "" || scope == "global" {
		p, _, err := manifest.EnsureGlobal()
		return p, err
	}
	if scope != "project" {
		return "", fmt.Errorf("scope must be global or project")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	p, ok := manifest.FindProject(cwd)
	if !ok {
		return "", fmt.Errorf("no project manifest; use global or run sm init in a project")
	}
	return p, nil
}
func valueOrGenerate(value, spec string) (string, error) {
	if value != "" && spec != "" {
		return "", fmt.Errorf("choose a value or generation, not both")
	}
	if spec != "" {
		return generate.Value(spec)
	}
	return value, nil
}
func (s *Server) add(w http.ResponseWriter, r *http.Request) {
	var req addRequest
	if err := decode(r, &req); err != nil {
		writeError(w, 400, err)
		return
	}
	if !manifest.ValidName(req.Name) {
		writeError(w, 400, fmt.Errorf("invalid secret name"))
		return
	}
	value, err := valueOrGenerate(req.Value, req.Generate)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	p, err := target(req.Scope)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	if err := secrets.AddBatch(p, []secrets.Input{{Name: req.Name, Value: value, Secret: manifest.Secret{Transport: req.Transport, Generate: req.Generate, Service: req.Service, Sensitive: req.Sensitive}}}, false); err != nil {
		writeError(w, 409, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "name": req.Name})
}

type detectRequest struct {
	Text  string `json:"text"`
	Scope string `json:"scope,omitempty"`
}

type detectView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Value     string `json:"value"`
	Service   string `json:"service,omitempty"`
	Sensitive bool   `json:"sensitive"`
	Source    string `json:"source"`
	Existing  bool   `json:"existing"`
	NewGroup  bool   `json:"newGroup"`
	Line      int    `json:"line"`
	Reason    string `json:"reason"`
	Conflict  string `json:"conflict"`
}

func (s *Server) detect(w http.ResponseWriter, r *http.Request) {
	var req detectRequest
	if err := decode(r, &req); err != nil {
		writeError(w, 400, err)
		return
	}
	if len(req.Text) > 128<<10 {
		writeError(w, 400, fmt.Errorf("paste is too large (128 KiB limit)"))
		return
	}
	cwd, err := os.Getwd()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	loaded, err := manifest.LoadOptional(cwd)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	merged, err := importManifest(loaded, req.Scope)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	groups := map[string]bool{}
	for _, group := range merged.Services() {
		groups[group] = true
	}
	report := detect.Analyze(req.Text)
	suggestions := report.Suggestions
	lookup := importLookup(merged)
	out := make([]detectView, 0, len(suggestions))
	for _, suggestion := range suggestions {
		_, exists := merged.Secrets[suggestion.Name]
		out = append(out, detectView{
			ID:        suggestion.ID,
			Name:      suggestion.Name,
			Value:     suggestion.Value,
			Service:   suggestion.Service,
			Sensitive: suggestion.Sensitive,
			Source:    suggestion.Source,
			Existing:  exists,
			NewGroup:  suggestion.Service != "" && !groups[suggestion.Service],
			Line:      suggestion.Line,
			Reason:    suggestion.Reason,
			Conflict:  lookup(suggestion.Name, suggestion.Value),
		})
	}
	writeJSON(w, 200, map[string]any{"suggestions": out, "warnings": report.Warnings})
}

type detectedEdit struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Value     *string `json:"value,omitempty"`
	Service   *string `json:"service,omitempty"`
	Sensitive *bool   `json:"sensitive,omitempty"`
}

type addDetectedRequest struct {
	Text    string            `json:"text"`
	Names   []string          `json:"names"`
	Renames map[string]string `json:"renames"`
	Scope   string            `json:"scope"`
	Entries []detectedEdit    `json:"entries,omitempty"`
}

// importLookup compares locally without returning stored values to the UI.
func importLookup(m *manifest.Manifest) func(string, string) string {
	id, err := keys.Get()
	var v *vaultfile.Vault
	if err == nil {
		if vp, e := keys.VaultPath(); e == nil {
			v, _ = vaultfile.Open(vp, id)
		}
	}
	return func(name, value string) string {
		sec, exists := m.Secrets[name]
		if !exists {
			return "new"
		}
		if v == nil {
			return "unavailable"
		}
		ref, _ := manifest.ParseRef(sec.Ref)
		stored, found, err := v.Get(ref.Path)
		if err != nil || !found {
			return "unavailable"
		}
		if stored == value {
			return "same"
		}
		return "different"
	}
}

func importManifest(l *manifest.Loaded, scope string) (*manifest.Manifest, error) {
	var m *manifest.Manifest
	switch scope {
	case "", "global":
		m = l.Global
	case "project":
		if l.Project == nil {
			return nil, fmt.Errorf("no project manifest found")
		}
		m = l.Project
	default:
		return nil, fmt.Errorf("scope must be global or project")
	}
	if m == nil {
		m = &manifest.Manifest{Secrets: map[string]manifest.Secret{}}
	}
	return m, nil
}

func prepareDetected(req addDetectedRequest) ([]secrets.Input, error) {
	if len(req.Text) > 128<<10 {
		return nil, fmt.Errorf("paste is too large (128 KiB limit)")
	}
	parsed := detect.Parse(req.Text)
	byID := map[string]detect.Suggestion{}
	byName := map[string]detect.Suggestion{}
	for _, s := range parsed {
		byID[s.ID] = s
		byName[s.Name] = s
	}
	entries := req.Entries
	if len(entries) == 0 {
		for _, name := range req.Names {
			s, ok := byName[name]
			if !ok {
				return nil, fmt.Errorf("selected entry was not detected; parse the text again")
			}
			edited := name
			if renamed, ok := req.Renames[name]; ok {
				edited = renamed
			}
			entries = append(entries, detectedEdit{ID: s.ID, Name: edited})
		}
	}
	if len(entries) == 0 || len(entries) > 50 {
		return nil, fmt.Errorf("select between 1 and 50 entries")
	}
	seenID, seenName := map[string]bool{}, map[string]bool{}
	var inputs []secrets.Input
	for _, edit := range entries {
		s, ok := byID[edit.ID]
		if !ok || seenID[edit.ID] {
			return nil, fmt.Errorf("invalid or repeated entry selection; parse the text again")
		}
		seenID[edit.ID] = true
		name := strings.TrimSpace(edit.Name)
		if !manifest.ValidName(name) || seenName[name] {
			return nil, fmt.Errorf("entry names must be valid and unique")
		}
		seenName[name] = true
		if edit.Value != nil {
			s.Value = *edit.Value
		}
		if edit.Service != nil {
			s.Service = strings.TrimSpace(*edit.Service)
		}
		if s.Service != "" && !manifest.ValidService(s.Service) {
			return nil, fmt.Errorf("group names must use letters, digits, dot, dash or underscore (max 32)")
		}
		if edit.Sensitive != nil {
			s.Sensitive = *edit.Sensitive
		}
		if s.Value == "" || strings.ContainsRune(s.Value, 0) || len(s.Value) > 1<<20 {
			return nil, fmt.Errorf("each value must be non-empty, without NUL bytes, and at most 1 MiB")
		}
		sensitive := s.Sensitive
		inputs = append(inputs, secrets.Input{Name: name, Value: s.Value, Secret: manifest.Secret{Service: s.Service, Sensitive: &sensitive}})
	}
	return inputs, nil
}

func (s *Server) reviewDetected(w http.ResponseWriter, r *http.Request) {
	var req addDetectedRequest
	if err := decode(r, &req); err != nil {
		writeError(w, 400, err)
		return
	}
	inputs, err := prepareDetected(req)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	cwd, err := os.Getwd()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	l, err := manifest.LoadOptional(cwd)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	m, err := importManifest(l, req.Scope)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	lookup := importLookup(m)
	items := []map[string]string{}
	for _, in := range inputs {
		items = append(items, map[string]string{"name": in.Name, "conflict": lookup(in.Name, in.Value)})
	}
	writeJSON(w, 200, map[string]any{"entries": items})
}

func (s *Server) addDetected(w http.ResponseWriter, r *http.Request) {
	var req addDetectedRequest
	if err := decode(r, &req); err != nil {
		writeError(w, 400, err)
		return
	}
	inputs, err := prepareDetected(req)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	p, err := target(req.Scope)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	if err := secrets.AddBatch(p, inputs, true); err != nil {
		writeError(w, 409, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "count": len(inputs)})
}

type groupRequest struct {
	Name    string `json:"name"`
	Scope   string `json:"scope"`
	Service string `json:"service"`
}

func (s *Server) service(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From  string   `json:"from"`
		To    string   `json:"to"`
		Scope string   `json:"scope"`
		Names []string `json:"names"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, 400, err)
		return
	}
	p, err := target(req.Scope)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	names, err := secrets.MoveService(p, req.From, req.To, req.Names)
	if err != nil {
		writeError(w, 409, err)
		return
	}
	writeJSON(w, 200, map[string]any{"names": names})
}

func (s *Server) group(w http.ResponseWriter, r *http.Request) {
	var req groupRequest
	if err := decode(r, &req); err != nil {
		writeError(w, 400, err)
		return
	}
	if !manifest.ValidName(req.Name) {
		writeError(w, 400, fmt.Errorf("invalid secret name"))
		return
	}
	p, err := target(req.Scope)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	if err := secrets.SetService(p, req.Name, req.Service); err != nil {
		writeError(w, 409, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "name": req.Name, "service": req.Service})
}

type rotateRequest struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Generate string `json:"generate"`
}

func (s *Server) rotate(w http.ResponseWriter, r *http.Request) {
	var req rotateRequest
	if err := decode(r, &req); err != nil {
		writeError(w, 400, err)
		return
	}
	value, err := valueOrGenerate(req.Value, req.Generate)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	cwd, err := os.Getwd()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	if err := secrets.Rotate(cwd, req.Name, value); err != nil {
		writeError(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

type importRequest struct {
	Data    string   `json:"data"`
	Preview bool     `json:"preview"`
	Names   []string `json:"names"`
}

func (s *Server) bulkImport(w http.ResponseWriter, r *http.Request) {
	var req importRequest
	if err := decode(r, &req); err != nil {
		writeError(w, 400, err)
		return
	}
	vars, err := resolve.ParseDotenv([]byte(req.Data))
	if err != nil {
		writeError(w, 400, fmt.Errorf("invalid dotenv input; use one NAME=value assignment per line"))
		return
	}
	names := resolve.Keys([]byte(req.Data))
	available := []string{}
	for _, name := range names {
		if vars[name] != "" && !strings.HasPrefix(vars[name], "sm://") {
			available = append(available, name)
		}
	}
	if req.Preview {
		writeJSON(w, 200, map[string]any{"names": available})
		return
	}
	if len(req.Names) == 0 {
		writeError(w, 400, fmt.Errorf("select at least one secret"))
		return
	}
	inputs := []secrets.Input{}
	for _, name := range req.Names {
		value, ok := vars[name]
		if !ok {
			writeError(w, 400, fmt.Errorf("selected name not found"))
			return
		}
		inputs = append(inputs, secrets.Input{Name: name, Value: value})
	}
	p, err := target("global")
	if err != nil {
		writeError(w, 500, err)
		return
	}
	if err := secrets.AddBatch(p, inputs, true); err != nil {
		writeError(w, 409, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "count": len(inputs)})
}

type agentView struct {
	Name   string `json:"name"`
	Detail string `json:"detail"`
	Status string `json:"status"`
}

func (s *Server) agents(w http.ResponseWriter, r *http.Request) {
	exe, err := os.Executable()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	out := []agentView{}
	for _, t := range wireup.Detect(exe, home) {
		out = append(out, agentView{t.Name, t.Detail, t.Status()})
	}
	writeJSON(w, 200, map[string]any{"agents": out})
}

func (s *Server) mcpConfig(w http.ResponseWriter, r *http.Request) {
	exe, err := os.Executable()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"snippets": wireup.Snippets(exe)})
}

type setupRequest struct {
	Only   string `json:"only"`
	Remove bool   `json:"remove"`
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	var req setupRequest
	if err := decode(r, &req); err != nil {
		writeError(w, 400, err)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	results := []map[string]any{}
	for _, t := range wireup.Detect(exe, home) {
		if req.Only != "" && req.Only != t.Name {
			continue
		}
		var status string
		var err error
		if req.Remove {
			status, err = t.Remove()
		} else {
			status, err = t.Apply()
		}
		item := map[string]any{"name": t.Name, "status": status, "removed": req.Remove}
		if err != nil {
			if req.Remove {
				item["status"] = "Could not remove the sm entry; inspect the harness configuration."
			} else {
				item["status"] = "Configuration failed; existing configuration was preserved. Use sm setup for diagnostics."
			}
			item["failed"] = true
		}
		results = append(results, item)
	}
	if req.Only != "" && len(results) == 0 {
		writeError(w, 404, fmt.Errorf("harness not detected"))
		return
	}
	writeJSON(w, 200, map[string]any{"results": results})
}

type doctorRequest struct {
	History bool `json:"history"`
}

func (s *Server) doctor(w http.ResponseWriter, r *http.Request) {
	var req doctorRequest
	if err := decode(r, &req); err != nil {
		writeError(w, 400, err)
		return
	}
	cwd, err := os.Getwd()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	l, err := manifest.LoadLayers(cwd)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	if len(l.Merged().Secrets) == 0 {
		writeJSON(w, 200, map[string]any{"output": "No registered values to check. Add credentials before scanning.", "exit": 2})
		return
	}
	id, err := keys.Get()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	vp, err := keys.VaultPath()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	v, err := vaultfile.Open(vp, id)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	var known []scan.Secret
	var names []string
	for name, sec := range l.Merged().Secrets {
		if !sec.IsSensitive() {
			continue // config values are not leaks
		}
		names = append(names, name)
		ref, _ := manifest.ParseRef(sec.Ref)
		if val, found, _ := v.Get(ref.Path); found {
			known = append(known, scan.Secret{Name: name, Value: val})
		}
	}
	home, _ := os.UserHomeDir()
	if l.ProjectPath != "" {
		cwd = filepath.Dir(l.ProjectPath)
	}
	result := scan.Run(scan.Options{ProjectDir: cwd, HomeDir: home, NoHistory: !req.History, Depth: 500}, known, names)
	var out strings.Builder
	fmt.Fprintf(&out, "%d finding(s) in %d scanned files; %d files skipped.\n", len(result.Findings), result.Scanned, result.Skipped)
	for _, f := range result.Findings {
		fmt.Fprintf(&out, "%s — %s (%s)\n", f.Location, f.Name, f.Kind)
	}
	for _, warning := range result.Warnings {
		fmt.Fprintln(&out, warning)
	}
	fmt.Fprintln(&out, "Only registered exact values and managed assignments are checked. Encoded, rotated or unregistered values may be missed.")
	code := 0
	if len(result.Findings) > 0 {
		code = 1
	} else if len(result.Warnings) > 0 {
		code = 2
	}
	writeJSON(w, 200, map[string]any{"output": out.String(), "exit": code})
}

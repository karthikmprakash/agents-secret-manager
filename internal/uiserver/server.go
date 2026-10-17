// Package uiserver serves the embedded desktop UI on authenticated loopback.
package uiserver

import (
	"bytes"
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
	"github.com/karthikmprakash/agents-secret-manager/internal/wireup"
)

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
	mux.HandleFunc("POST /api/initialize", s.auth(s.initialize))
	mux.HandleFunc("POST /api/add", s.auth(s.add))
	mux.HandleFunc("POST /api/group", s.auth(s.group))
	mux.HandleFunc("POST /api/rotate", s.auth(s.rotate))
	mux.HandleFunc("POST /api/import", s.auth(s.bulkImport))
	mux.HandleFunc("POST /api/detect", s.auth(s.detect))
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
}
type auditView struct {
	TS      string   `json:"ts"`
	Action  string   `json:"action"`
	Secrets []string `json:"secrets"`
	Cmd     string   `json:"cmd"`
}
type stateResponse struct {
	Vault           string       `json:"vault"`
	GlobalManifest  string       `json:"globalManifest"`
	ProjectManifest string       `json:"projectManifest"`
	ProjectName     string       `json:"projectName"`
	Initialized     bool         `json:"initialized"`
	VaultError      string       `json:"vaultError,omitempty"`
	AuditError      string       `json:"auditError,omitempty"`
	Secrets         []secretView `json:"secrets"`
	Audit           []auditView  `json:"audit"`
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
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return fmt.Errorf("request exceeds 1 MiB or could not be read")
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
		if v != nil {
			ref, _ := manifest.ParseRef(sec.Ref)
			_, found, _ := v.Get(ref.Path)
			status = "missing"
			if found {
				status = "present"
			}
		}
		resp.Secrets = append(resp.Secrets, secretView{Name: name, Scope: scope, Transport: sec.Transport, Ref: sec.Ref, Status: status, Service: sec.Service, Sensitive: sec.IsSensitive()})
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
	writeJSON(w, 200, resp)
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
	Text string `json:"text"`
}

type detectView struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Service   string `json:"service,omitempty"`
	Sensitive bool   `json:"sensitive"`
	Source    string `json:"source"`
	Existing  bool   `json:"existing"`
	NewGroup  bool   `json:"newGroup"`
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
	merged := loaded.Merged()
	groups := map[string]bool{}
	for _, group := range merged.Services() {
		groups[group] = true
	}
	suggestions := detect.Parse(req.Text)
	out := make([]detectView, 0, len(suggestions))
	for _, suggestion := range suggestions {
		_, exists := merged.Secrets[suggestion.Name]
		out = append(out, detectView{
			Name:      suggestion.Name,
			Value:     suggestion.Value,
			Service:   suggestion.Service,
			Sensitive: suggestion.Sensitive,
			Source:    suggestion.Source,
			Existing:  exists,
			NewGroup:  suggestion.Service != "" && !groups[suggestion.Service],
		})
	}
	writeJSON(w, 200, map[string]any{"suggestions": out})
}

type addDetectedRequest struct {
	Text    string            `json:"text"`
	Names   []string          `json:"names"`
	Renames map[string]string `json:"renames"`
	Scope   string            `json:"scope"`
}

func (s *Server) addDetected(w http.ResponseWriter, r *http.Request) {
	var req addDetectedRequest
	if err := decode(r, &req); err != nil {
		writeError(w, 400, err)
		return
	}
	if len(req.Text) > 128<<10 {
		writeError(w, 400, fmt.Errorf("paste is too large (128 KiB limit)"))
		return
	}
	if len(req.Names) == 0 || len(req.Names) > 50 {
		writeError(w, 400, fmt.Errorf("select between 1 and 50 suggestions"))
		return
	}
	wanted := map[string]bool{}
	for _, name := range req.Names {
		wanted[name] = true
	}
	var inputs []secrets.Input
	for _, suggestion := range detect.Parse(req.Text) {
		if !wanted[suggestion.Name] {
			continue
		}
		delete(wanted, suggestion.Name)
		name := suggestion.Name
		if renamed, ok := req.Renames[suggestion.Name]; ok {
			renamed = strings.TrimSpace(renamed)
			if !manifest.ValidName(renamed) {
				writeError(w, 400, fmt.Errorf("invalid name %q", renamed))
				return
			}
			name = renamed
		}
		var sensitive *bool
		if !suggestion.Sensitive {
			no := false
			sensitive = &no
		}
		inputs = append(inputs, secrets.Input{
			Name:  name,
			Value: suggestion.Value,
			Secret: manifest.Secret{
				Service:   suggestion.Service,
				Sensitive: sensitive,
			},
		})
	}
	if len(inputs) == 0 {
		writeError(w, 400, fmt.Errorf("none of the selected suggestions were detected"))
		return
	}
	if len(wanted) > 0 {
		missing := make([]string, 0, len(wanted))
		for name := range wanted {
			missing = append(missing, name)
		}
		sort.Strings(missing)
		writeError(w, 400, fmt.Errorf("could not detect: %s", strings.Join(missing, ", ")))
		return
	}
	p, err := target(req.Scope)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	if err := secrets.AddBatch(p, inputs, false); err != nil {
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
	Only string `json:"only"`
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
		status, err := t.Apply()
		item := map[string]any{"name": t.Name, "status": status}
		if err != nil {
			item["status"] = "Configuration failed; existing configuration was preserved. Use sm setup for diagnostics."
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

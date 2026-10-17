// Package uiserver serves the local sm desktop UI over loopback.
//
// Every request requires a per-run bearer token (also accepted as ?token= so
// the shell can load the page once). Responses never contain secret values.
package uiserver

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/karthikmprakash/agents-secret-manager/internal/audit"
	"github.com/karthikmprakash/agents-secret-manager/internal/config"
	"github.com/karthikmprakash/agents-secret-manager/internal/generate"
	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
	"github.com/karthikmprakash/agents-secret-manager/internal/wireup"
)

//go:embed ui/index.html
var uiFS embed.FS

// Server is a running UI server.
type Server struct {
	http  *http.Server
	URL   string
	token string
}

// Start binds 127.0.0.1 (random port when port is 0) and serves the UI.
func Start(port int) (*Server, error) {
	token, err := newToken()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}

	s := &Server{token: token}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.auth(s.index))
	mux.HandleFunc("/api/state", s.auth(s.state))
	mux.HandleFunc("/api/add", s.auth(s.add))
	mux.HandleFunc("/api/rotate", s.auth(s.rotate))
	mux.HandleFunc("/api/agents", s.auth(s.agents))
	mux.HandleFunc("/api/setup", s.auth(s.setup))
	mux.HandleFunc("/api/doctor", s.auth(s.doctor))

	addr := ln.Addr().(*net.TCPAddr)
	s.URL = fmt.Sprintf("http://127.0.0.1:%d/?token=%s", addr.Port, token)
	s.http = &http.Server{Handler: mux}
	go func() { _ = s.http.Serve(ln) }()
	return s, nil
}

// Close stops the server.
func (s *Server) Close() error { return s.http.Close() }

func newToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ok := r.Header.Get("Authorization") == "Bearer "+s.token ||
			r.URL.Query().Get("token") == s.token
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next(w, r)
	}
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := uiFS.ReadFile("ui/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// ---------------------------------------------------------------- API types

type secretView struct {
	Name      string `json:"name"`
	Scope     string `json:"scope"`
	Transport string `json:"transport"`
	Ref       string `json:"ref"`
	Status    string `json:"status"`
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
	Secrets         []secretView `json:"secrets"`
	Audit           []auditView  `json:"audit"`
}

// ------------------------------------------------------------------ helpers

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
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	return dec.Decode(v)
}

// loadTolerant returns the layers that exist; a missing manifest is not an
// error for the UI.
func loadTolerant(cwd string) *manifest.Loaded {
	l := &manifest.Loaded{}
	if gp, err := manifest.GlobalPath(); err == nil {
		if _, statErr := os.Stat(gp); statErr == nil {
			if m, err := manifest.Load(gp); err == nil {
				l.Global, l.GlobalPath = m, gp
			}
		}
	}
	if pp, ok := manifest.FindProject(cwd); ok {
		if m, err := manifest.Load(pp); err == nil {
			l.Project, l.ProjectPath = m, pp
		}
	}
	return l
}

func vaultStatuses(merged *manifest.Manifest) map[string]string {
	status := map[string]string{}
	identity, err := keys.Get()
	if err != nil {
		return status
	}
	vp, err := keys.VaultPath()
	if err != nil {
		return status
	}
	v, err := vaultfile.Open(vp, identity)
	if err != nil {
		return status
	}
	for name, s := range merged.Secrets {
		ref, err := manifest.ParseRef(s.Ref)
		if err != nil {
			status[name] = "invalid ref"
			continue
		}
		if _, found, _ := v.Get(ref.Path); found {
			status[name] = "present"
		} else {
			status[name] = "missing"
		}
	}
	return status
}

func runSelf(args ...string) (string, int) {
	exe, err := os.Executable()
	if err != nil {
		return err.Error(), 1
	}
	out, runErr := exec.Command(exe, args...).CombinedOutput()
	code := 0
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = 1
		}
	}
	return string(out), code
}

func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// ------------------------------------------------------------------ handlers

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	cwd, err := os.Getwd()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	loaded := loadTolerant(cwd)
	merged := loaded.Merged()
	status := vaultStatuses(merged)

	resp := stateResponse{
		GlobalManifest:  loaded.GlobalPath,
		ProjectManifest: loaded.ProjectPath,
		ProjectName:     merged.Project.Name,
		Secrets:         []secretView{},
		Audit:           []auditView{},
	}
	if vp, err := keys.VaultPath(); err == nil {
		resp.Vault = vp
	}

	for name, sec := range merged.Secrets {
		scope := "global"
		if loaded.Project != nil {
			if _, ok := loaded.Project.Secrets[name]; ok {
				scope = "project"
			}
		}
		st := status[name]
		if st == "" {
			st = "unknown"
		}
		resp.Secrets = append(resp.Secrets, secretView{
			Name:      name,
			Scope:     scope,
			Transport: sec.Transport,
			Ref:       sec.Ref,
			Status:    st,
		})
	}
	sort.Slice(resp.Secrets, func(i, j int) bool { return resp.Secrets[i].Name < resp.Secrets[j].Name })

	entries, _ := audit.Read(mustConfigDir())
	if n := len(entries); n > 0 {
		start := n - 10
		if start < 0 {
			start = 0
		}
		for i := n - 1; i >= start; i-- {
			e := entries[i]
			resp.Audit = append(resp.Audit, auditView{TS: e.TS, Action: e.Action, Secrets: e.Secrets, Cmd: e.Cmd})
		}
	}

	writeJSON(w, 200, resp)
}

func mustConfigDir() string {
	dir, _ := config.Dir()
	return dir
}

type addRequest struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Scope     string `json:"scope"`
	Transport string `json:"transport"`
	Generate  string `json:"generate"`
}

func (s *Server) add(w http.ResponseWriter, r *http.Request) {
	var req addRequest
	if err := decode(r, &req); err != nil {
		writeError(w, 400, err)
		return
	}
	name := strings.TrimSpace(req.Name)
	if !validEnvName(name) {
		writeError(w, 400, fmt.Errorf("name must be letters, digits and underscore, starting with a letter or underscore"))
		return
	}

	cwd, err := os.Getwd()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	loaded := loadTolerant(cwd)
	if _, exists := loaded.Merged().Secrets[name]; exists {
		writeError(w, 409, fmt.Errorf("%s is already declared — rotate it instead", name))
		return
	}

	transport := req.Transport
	if transport == "" {
		transport = manifest.TransportEnv
	}
	if transport != manifest.TransportEnv && transport != manifest.TransportFile {
		writeError(w, 400, fmt.Errorf("transport must be env or file"))
		return
	}

	value := req.Value
	if req.Generate != "" {
		var err error
		value, err = generate.Value(req.Generate)
		if err != nil {
			writeError(w, 400, err)
			return
		}
	}
	if value == "" {
		writeError(w, 400, fmt.Errorf("value or generate is required"))
		return
	}

	var target string
	if req.Scope == "project" {
		if loaded.Project == nil {
			writeError(w, 400, fmt.Errorf("no project manifest here — run `sm init` in the project first"))
			return
		}
		target = loaded.ProjectPath
	} else {
		gp, _, err := manifest.EnsureGlobal()
		if err != nil {
			writeError(w, 500, err)
			return
		}
		target = gp
	}

	ref := "vault://" + strings.ToLower(name)
	parsed, err := manifest.ParseRef(ref)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	identity, err := keys.Get()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	vp, err := keys.VaultPath()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	v, err := vaultfile.Open(vp, identity)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	if err := v.Set(parsed.Path, value); err != nil {
		writeError(w, 500, err)
		return
	}
	if err := manifest.AppendSecret(target, name, manifest.Secret{Ref: ref, Transport: transport}); err != nil {
		writeError(w, 500, err)
		return
	}

	writeJSON(w, 200, map[string]any{"ok": true, "name": name, "ref": ref, "scope": req.Scope})
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
	cwd, err := os.Getwd()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	merged := loadTolerant(cwd).Merged()
	sec, ok := merged.Secrets[req.Name]
	if !ok {
		writeError(w, 404, fmt.Errorf("%s is not declared", req.Name))
		return
	}
	value := req.Value
	if req.Generate != "" {
		value, err = generate.Value(req.Generate)
		if err != nil {
			writeError(w, 400, err)
			return
		}
	}
	if value == "" {
		writeError(w, 400, fmt.Errorf("value or generate is required"))
		return
	}
	ref, err := manifest.ParseRef(sec.Ref)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	identity, err := keys.Get()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	vp, err := keys.VaultPath()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	v, err := vaultfile.Open(vp, identity)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	if err := v.Set(ref.Path, value); err != nil {
		writeError(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "name": req.Name})
}

type agentView struct {
	Name   string `json:"name"`
	Detail string `json:"detail"`
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
		out = append(out, agentView{Name: t.Name, Detail: t.Detail})
	}
	writeJSON(w, 200, map[string]any{"agents": out})
}

type setupRequest struct {
	Only string `json:"only"`
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	var req setupRequest
	_ = decode(r, &req)

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
		if req.Only != "" && t.Name != req.Only {
			continue
		}
		item := map[string]any{"name": t.Name}
		status, err := t.Apply()
		if err != nil {
			item["status"] = err.Error()
			item["failed"] = true
		} else {
			item["status"] = status
		}
		results = append(results, item)
	}
	writeJSON(w, 200, map[string]any{"results": results})
}

type doctorRequest struct {
	History bool `json:"history"`
}

func (s *Server) doctor(w http.ResponseWriter, r *http.Request) {
	var req doctorRequest
	_ = decode(r, &req)
	args := []string{"doctor"}
	if !req.History {
		args = append(args, "--no-history")
	}
	out, code := runSelf(args...)
	writeJSON(w, 200, map[string]any{"output": out, "exit": code})
}

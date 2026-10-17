package uiserver

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/karthikmprakash/agents-secret-manager/internal/audit"
	"github.com/karthikmprakash/agents-secret-manager/internal/config"
	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/recovery"
)

// One memory-hard password operation at a time, even across UI server instances.
var recoveryGate sync.Mutex

type recoveryRequest struct {
	Passphrase string `json:"passphrase"`
	Data       []byte `json:"data,omitempty"`
	Confirm    bool   `json:"confirm,omitempty"`
}

func recoveryEmpty(dir string) bool {
	for _, name := range []string{"vault.age", "manifest.toml"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func recoveryAudit(dir, action string) error {
	return audit.Append(dir, audit.Entry{TS: time.Now().UTC().Format(time.RFC3339), Session: audit.NewSession(), Action: action, Cmd: "sm " + action})
}

func (s *Server) exportRecovery(w http.ResponseWriter, r *http.Request) {
	var req recoveryRequest
	if err := decode(r, &req); err != nil {
		writeError(w, 400, err)
		return
	}
	if !recoveryGate.TryLock() {
		writeError(w, 429, fmt.Errorf("another recovery operation is running; retry shortly"))
		return
	}
	defer recoveryGate.Unlock()
	dir, err := config.Dir()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	id, err := keys.Get()
	if err != nil {
		writeError(w, 400, fmt.Errorf("unlock the vault before backing up"))
		return
	}
	data, err := recovery.Export(dir, id, req.Passphrase)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	if err := recoveryAudit(dir, "backup"); err != nil {
		writeError(w, 500, fmt.Errorf("could not record backup attempt"))
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="sm-recovery.age"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) inspectRecovery(w http.ResponseWriter, r *http.Request) { s.readRecovery(w, r, false) }
func (s *Server) restoreRecovery(w http.ResponseWriter, r *http.Request) { s.readRecovery(w, r, true) }

func (s *Server) readRecovery(w http.ResponseWriter, r *http.Request, restore bool) {
	var req recoveryRequest
	if err := decodeLimit(r, &req, 44<<20); err != nil {
		writeError(w, 400, err)
		return
	}
	if restore && !req.Confirm {
		writeError(w, 400, fmt.Errorf("confirm restoring into an empty vault"))
		return
	}
	if !recoveryGate.TryLock() {
		writeError(w, 429, fmt.Errorf("another recovery operation is running; retry shortly"))
		return
	}
	defer recoveryGate.Unlock()
	contents, err := recovery.Open(req.Data, req.Passphrase)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	dir, err := config.Dir()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	empty := recoveryEmpty(dir)
	if !restore {
		writeJSON(w, 200, map[string]any{"summary": contents.Summary(), "canRestore": empty})
		return
	}
	if !empty {
		writeError(w, 409, fmt.Errorf("restore requires an empty vault directory; existing data was not changed"))
		return
	}
	id, err := keys.Get()
	if errors.Is(err, keys.ErrNotFound) {
		id, err = keys.Create()
	}
	if err != nil {
		writeError(w, 400, fmt.Errorf("could not create or unlock the local identity"))
		return
	}
	if err := contents.Restore(dir, id); err != nil {
		writeError(w, 409, err)
		return
	}
	if err := recoveryAudit(dir, "restore"); err != nil {
		writeJSON(w, 200, map[string]any{"ok": true, "warning": "Restore completed, but its audit entry could not be written."})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

package uiserver

import (
	"filippo.io/age"
	"fmt"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/secrets"
	"os"
	"testing"
	"time"
)

// Opt-in browser test fixture. It never opens the real Keychain or user vault.
// SM_UI_PREVIEW=1 go test -v ./internal/uiserver -run TestInteractivePreview -timeout 16m
func TestInteractivePreview(t *testing.T) {
	if os.Getenv("SM_UI_PREVIEW") != "1" {
		t.Skip("interactive browser fixture")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SM_CONFIG_DIR", t.TempDir())
	t.Chdir(home)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SM_IDENTITY", id.String())
	if os.Getenv("SM_UI_PREVIEW_SEEDED") == "1" {
		if err := secrets.Initialize(); err != nil {
			t.Fatal(err)
		}
		p, _ := manifest.GlobalPath()
		if err := secrets.AddBatch(p, []secrets.Input{{Name: "AWS_ACCESS_KEY_ID", Value: "demo-key-not-real"}, {Name: "AWS_SECRET_ACCESS_KEY", Value: "demo-secret-not-real"}, {Name: "MODAL_TOKEN_ID", Value: "demo-modal-not-real"}}, false); err != nil {
			t.Fatal(err)
		}
	}
	s, err := Start(0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	fmt.Println("UI_PREVIEW_URL=" + s.URL)
	<-time.After(15 * time.Minute)
}

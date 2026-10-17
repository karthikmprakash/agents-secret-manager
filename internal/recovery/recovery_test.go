package recovery

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
)

func TestEncryptedRecoveryRoundTripAndRefusal(t *testing.T) {
	source := t.TempDir()
	id, _ := age.GenerateX25519Identity()
	v, err := vaultfile.Open(filepath.Join(source, "vault.age"), id.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := v.SetBatch(map[string]string{"global/KEY": "dummy-private-value", "projects/orphan/URL": "https://example.org"}); err != nil {
		t.Fatal(err)
	}
	body := "# keep comments\n[secrets.KEY]\nref = \"vault://global/KEY\"\nservice = \"demo\"\n"
	if err := os.WriteFile(filepath.Join(source, "manifest.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	password := "test recovery passphrase only"
	data, err := Export(source, id.String(), password)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"dummy-private-value", "keep comments", "projects/orphan/URL", id.String()} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatal("archive contains unencrypted data")
		}
	}
	contents, err := Open(data, password)
	if err != nil {
		t.Fatal(err)
	}
	if summary := contents.Summary(); summary.Entries != 1 || summary.StoredValues != 2 {
		t.Fatalf("summary = %+v", summary)
	}
	destination := t.TempDir()
	newID, _ := age.GenerateX25519Identity()
	if err := contents.Restore(destination, newID.String()); err != nil {
		t.Fatal(err)
	}
	restored, err := vaultfile.Open(filepath.Join(destination, "vault.age"), newID.String())
	if err != nil {
		t.Fatal(err)
	}
	value, found, _ := restored.Get("global/KEY")
	if !found || value != "dummy-private-value" {
		t.Fatal("value did not survive recovery")
	}
	if _, err := vaultfile.Open(filepath.Join(destination, "vault.age"), id.String()); err == nil {
		t.Fatal("restore should use the new identity")
	}
	if err := contents.Restore(destination, newID.String()); err == nil {
		t.Fatal("existing vault must not be overwritten")
	}
	if _, err := Open(data, "wrong passphrase"); err == nil {
		t.Fatal("wrong password accepted")
	}
	tampered := append([]byte(nil), data...)
	tampered[len(tampered)-1] ^= 1
	if _, err := Open(tampered, password); err == nil {
		t.Fatal("damaged ciphertext accepted")
	}
	for _, name := range []string{"vault.age", "manifest.toml"} {
		fi, err := os.Stat(filepath.Join(destination, name))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("wrong recovery file permissions")
		}
	}
	if _, err := Export(source, id.String(), "short"); err == nil {
		t.Fatal("weak passphrase accepted")
	}
	if _, err := Open([]byte("not an archive"), password); err == nil {
		t.Fatal("invalid archive accepted")
	}
}

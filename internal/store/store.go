// Package store writes local audit records. Same-user storage is not tamper-proof.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/event"
)

type Run struct {
	ID string `json:"id"`
	Project string `json:"project"`
	Agent string `json:"agent"`
	Status string `json:"status"`
	Mode string `json:"mode"`
	Branch string `json:"branch"`
	PolicyHash string `json:"policy_hash"`
	Socket string `json:"socket"`
	Control string `json:"control"`
	Started time.Time `json:"started"`
	Finished *time.Time `json:"finished,omitempty"`
	Events int `json:"events"`
	Warnings int `json:"warnings"`
	Pauses int `json:"pauses"`
	Kills int `json:"kills"`
	Violations int `json:"violations"`
	ExitCode int `json:"exit_code"`
	Rule string `json:"rule,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type Store struct { Dir string; log *os.File }

func ProjectDir(root string) (string, error) {
	base := os.Getenv("SAGA_WATCHDOG_STATE_DIR")
	if base == "" {
		home, err := os.UserHomeDir(); if err != nil { return "", err }
		switch runtime.GOOS {
		case "darwin": base = filepath.Join(home, "Library", "Application Support", "saga-watchdog")
		default:
			base = os.Getenv("XDG_STATE_HOME")
			if base == "" { base = filepath.Join(home, ".local", "state") }
			base = filepath.Join(base, "saga-watchdog")
		}
	}
	base, err := filepath.Abs(base); if err != nil { return "", err }
	// Keep audit I/O outside the watched tree, preventing recursive events.
	rel, err := filepath.Rel(root, base)
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) { return "", errors.New("state directory must be outside the project") }
	h := sha256.Sum256([]byte(root))
	return filepath.Join(base, hex.EncodeToString(h[:8])), nil
}

func privateDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil { return err }
	info, err := os.Lstat(dir); if err != nil { return err }
	if info.Mode()&os.ModeSymlink!=0 { return errors.New("state directory must not be a symlink") }
	return os.Chmod(dir, 0700)
}

func Prepare(root string) (string, error) {
	dir, err := ProjectDir(root); if err != nil { return "", err }
	if err = privateDir(dir); err != nil { return "", err }
	physical, err := filepath.EvalSymlinks(dir); if err != nil { return "", err }
	project, err := filepath.EvalSymlinks(root); if err != nil { return "", err }
	rel, err := filepath.Rel(project, physical)
	if err==nil&&rel!=".."&&!strings.HasPrefix(rel,".."+string(filepath.Separator)){return "",errors.New("state directory resolves inside the project")}
	dir=physical
	f, err := os.CreateTemp(dir, ".write-test-"); if err != nil { return "", err }
	name := f.Name(); if err = f.Close(); err != nil { return "", err }; if err = os.Remove(name); err != nil { return "", err }
	return dir, nil
}

func Create(root string, r Run) (*Store, error) {
	base, err := Prepare(root); if err != nil { return nil, err }
	if !ValidID(r.ID) { return nil, errors.New("invalid run ID") }
	dir := filepath.Join(base, r.ID)
	if err = os.Mkdir(dir, 0700); err != nil { return nil, err }
	f, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0600)
	if err != nil { return nil, err }
	s := &Store{Dir:dir,log:f}
	if err = s.Save(r, false); err != nil { f.Close(); return nil, err }
	return s, nil
}

func ValidID(id string) bool {
	if !strings.HasPrefix(id, "run_") || len(id) > 96 || len(id) < 8 { return false }
	for _, c := range id { if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') { return false } }
	return true
}

func (s *Store) Append(e event.Event) error {
	b, err := json.Marshal(e.Sanitized()); if err != nil { return err }
	_, err = s.log.Write(append(b, '\n')); return err
}

func (s *Store) Save(r Run, summary bool) error {
	r.Reason = event.Redact(r.Reason); r.Project = event.Redact(r.Project); r.Agent = event.Redact(r.Agent); r.Branch = event.Redact(r.Branch)
	b, err := json.MarshalIndent(r, "", "  "); if err != nil { return err }
	name := "run.json"; if summary { name = "summary.json" }
	f, err := os.CreateTemp(s.Dir, ".record-"); if err != nil { return err }
	tmp := f.Name(); defer os.Remove(tmp)
	if _, err = f.Write(b); err != nil { f.Close(); return err }
	if err = f.Sync(); err != nil { f.Close(); return err }
	if err = f.Close(); err != nil { return err }
	return os.Rename(tmp, filepath.Join(s.Dir,name))
}

func (s *Store) Close() error { a := s.log.Sync(); b := s.log.Close(); return errors.Join(a,b) }

func Locate(root, id string) (string, Run, error) {
	base, err := ProjectDir(root); if err != nil { return "", Run{}, err }
	if id == "" {
		entries, err := os.ReadDir(base); if err != nil { return "", Run{}, err }
		var ids []string; for _, e := range entries { if e.IsDir() && ValidID(e.Name()) { ids = append(ids,e.Name()) } }
		sort.Strings(ids); if len(ids)==0 { return "", Run{}, errors.New("no runs in this project") }; id = ids[len(ids)-1]
	}
	if !ValidID(id) { return "", Run{}, errors.New("invalid run ID") }
	dir := filepath.Join(base,id)
	f, err := os.Open(filepath.Join(dir,"run.json")); if err != nil { return "", Run{}, err }; defer f.Close()
	var r Run; if err = json.NewDecoder(io.LimitReader(f, 65536)).Decode(&r); err != nil { return "",r,err }
	if r.ID != id { return "",r,fmt.Errorf("run record ID mismatch") }
	return dir,r,nil
}

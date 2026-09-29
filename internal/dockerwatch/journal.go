package dockerwatch

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/odbgrowth/saga-watchdog/internal/event"
)

const logBackups = 3

type Journal struct {
	dir            string
	lock, log      *os.File
	size, maxBytes int64
}

func privateFile(path string, flags int) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("observer state files must be private regular files")
	}
	return os.OpenFile(path, flags, 0600)
}

func OpenJournal(dir string) (*Journal, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("state_dir must be a private directory (chmod 700), not a symlink")
	}
	lock, err := privateFile(filepath.Join(dir, "observer.lock"), os.O_CREATE|os.O_RDWR)
	if err != nil {
		return nil, err
	}
	if err = lockFile(lock); err != nil {
		lock.Close()
		return nil, err
	}
	j := &Journal{dir: dir, lock: lock, maxBytes: 10 * 1024 * 1024}
	if err = j.openLog(); err != nil {
		j.Close()
		return nil, err
	}
	return j, nil
}

func (j *Journal) openLog() error {
	f, err := privateFile(filepath.Join(j.dir, "events.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	j.log, j.size = f, info.Size()
	return nil
}

func (j *Journal) Append(e event.Event) error {
	if j.log == nil {
		return errors.New("observer journal is closed")
	}
	b, err := json.Marshal(e.Sanitized())
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if j.size > 0 && j.size+int64(len(b)) > j.maxBytes {
		if err := j.log.Close(); err != nil {
			return err
		}
		j.log = nil
		base := filepath.Join(j.dir, "events.jsonl")
		if err := os.Remove(fmt.Sprintf("%s.%d", base, logBackups)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for n := logBackups - 1; n >= 0; n-- {
			src := base
			if n > 0 {
				src = fmt.Sprintf("%s.%d", base, n)
			}
			if err := os.Rename(src, fmt.Sprintf("%s.%d", base, n+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if err := j.openLog(); err != nil {
			return err
		}
	}
	n, err := j.log.Write(b)
	j.size += int64(n)
	if err != nil {
		return err
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	return j.log.Sync()
}

func (j *Journal) Save(s Snapshot) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(j.dir, ".status-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(j.dir, "status.json"))
}

func (j *Journal) Close() error {
	var err error
	if j.log != nil {
		err = j.log.Close()
		j.log = nil
	}
	if j.lock != nil {
		err = errors.Join(err, j.lock.Close())
		j.lock = nil
	}
	return err
}

func ReadSnapshot(c Config) (Snapshot, error) {
	var s Snapshot
	f, err := os.Open(filepath.Join(c.StateDir, "status.json"))
	if err != nil {
		return s, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil {
		return s, err
	}
	if len(b) > 1024*1024 {
		return s, errors.New("observer status exceeds 1 MiB")
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, errors.New("invalid observer status")
	}
	if s.Version != 1 || s.ConfigID != c.ID() {
		return s, errors.New("status belongs to a different configuration; restart the observer with this config")
	}
	return s, nil
}

// CopyHistory returns oldest retained events first, including the active file.
// The observer can rotate concurrently; these files are not an immutable archive.
func CopyHistory(dir string, out io.Writer) error {
	for n := logBackups; n >= 0; n-- {
		path := filepath.Join(dir, "events.jsonl")
		if n > 0 {
			path = fmt.Sprintf("%s.%d", path, n)
		}
		f, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) && n > 0 {
			continue
		}
		if err != nil {
			return err
		}
		info, statErr := f.Stat()
		if statErr != nil {
			f.Close()
			return statErr
		}
		_, copyErr := io.CopyN(out, f, info.Size())
		closeErr := f.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			return err
		}
	}
	return nil
}

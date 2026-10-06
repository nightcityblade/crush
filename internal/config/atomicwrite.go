package config

import (
	"os"
	"path/filepath"
	"time"
)

// atomicWriteFile writes data to a file atomically by writing to a unique
// temporary file in the same directory and renaming it into place. This
// prevents concurrent readers from observing a partially-written file.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	path = filepath.Clean(path)
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := renameFile(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// transientRetryBudget bounds how long a transient failure is retried.
const transientRetryBudget = 2 * time.Second

// renameFile renames tmp over path. On Windows the rename fails with
// ERROR_ACCESS_DENIED or ERROR_SHARING_VIOLATION while another process
// (antivirus, search indexer) or a concurrent reader briefly holds a
// handle on the destination, so transient failures are retried.
func renameFile(tmp, path string) error {
	return retryTransient(func() error { return os.Rename(tmp, path) })
}

// readFile is os.ReadFile, retried while Windows briefly locks the file
// (another writer's renameFile, antivirus, the search indexer).
func readFile(path string) ([]byte, error) {
	var data []byte
	err := retryTransient(func() (err error) {
		data, err = os.ReadFile(path)
		return err
	})
	return data, err
}

// retryTransient runs op with backoff until it succeeds, fails with a
// non-transient error, or transientRetryBudget is spent.
func retryTransient(op func() error) error {
	var slept time.Duration
	delay := time.Millisecond
	for {
		err := op()
		if err == nil || !isTransientFileError(err) || slept >= transientRetryBudget {
			return err
		}
		time.Sleep(delay)
		slept += delay
		delay = min(delay*2, 50*time.Millisecond)
	}
}

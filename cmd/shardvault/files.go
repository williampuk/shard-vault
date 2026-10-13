package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
    "strings"

	"github.com/williampuk/shard-vault/internal/share"
	"golang.org/x/sys/unix"
)

// Nonblocking open prevents a FIFO from hanging recovery. No-follow plus fstat
// reject symlinks, devices, directories, and sockets before any bytes are read.
func readShareFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("share input must be a regular file, not a device, pipe, directory, or symlink")
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(share.MaxShareInputBytes+3)))
	if err != nil || len(data) > share.MaxShareInputBytes+2 {
		clear(data)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("share file is too large")
	}
	return data, nil
}

// Pin the destination directory by descriptor. Require it to exist, and reject
// group/other-writable destinations. The user must trust its ancestors and OS.
func exportRoot(dir string) (*os.Root, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open existing destination directory: %w", err)
	}
	info, err := root.Stat(".")
	if err != nil {
		root.Close()
		return nil, err
	}
	if info.Mode().Perm()&0022 != 0 {
		root.Close()
		return nil, errors.New("destination directory must not be writable by group or others")
	}
	return root, nil
}

func syncDirectory(root *os.Root) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func writeShare(root *os.Root, name string, s share.Share) error {
    return writeShareWithEncoding(root, name, s, false)
}

func writeShareWithEncoding(root *os.Root, name string, s share.Share, words bool) error {
    token, err := s.Token()
    if words {
        token, err = s.Words()
        if err == nil {
            parts := strings.Fields(token)
            // Keep the format label on its own line, with six words per line.
            var output strings.Builder
            output.WriteString(parts[0])
            for i, word := range parts[1:] {
                if i%6 == 0 {
                    output.WriteByte('\n')
                } else {
                    output.WriteByte(' ')
                }
                output.WriteString(word)
            }
            token = output.String()
        }
    }
    if err != nil {
        return err
    }
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		f.Close()
		if !keep {
			_ = root.Remove(name)
		}
	}()
	// Enforce and inspect permissions BEFORE exposing any share bytes.
	if err = f.Chmod(0600); err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return errors.New("filesystem cannot enforce private regular files; refusing export")
	}
	if _, err = io.WriteString(f, token+"\n"); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	keep = true
	if err = syncDirectory(root); err != nil {
		return fmt.Errorf("file written but directory sync failed; durability unconfirmed (file retained): %w", err)
	}
	return nil
}

func saveShare(path string, s share.Share) error {
    return saveShareWithEncoding(path, s, false)
}

func saveWords(path string, s share.Share) error {
    return saveShareWithEncoding(path, s, true)
}

func saveShareWithEncoding(path string, s share.Share, words bool) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if path == "" {
		return errors.New("empty path")
	}
	root, err := exportRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	return writeShareWithEncoding(root, filepath.Base(path), s, words)
}

func saveAll(dir string, shares []share.Share) error {
    return saveAllWithEncoding(dir, shares, false)
}

func saveAllWords(dir string, shares []share.Share) error {
    return saveAllWithEncoding(dir, shares, true)
}

func saveAllWithEncoding(dir string, shares []share.Share, words bool) error {
	if err := share.VerifyAll(shares, shares); err != nil {
		return err
	}
	if dir == "" || filepath.Clean(dir) == "." || filepath.Clean(dir) == "/" {
		return errors.New("choose a NEW non-root folder")
	}
	parent, err := exportRoot(filepath.Dir(dir))
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(dir)
	if err = parent.Mkdir(name, 0700); err != nil {
		return fmt.Errorf("new folder must not already exist: %w", err)
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return err
	}
	defer root.Close()
	info, err := root.Stat(".")
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("new folder is not private; no shares written")
	}
	if err := syncDirectory(parent); err != nil {
		return fmt.Errorf("cannot sync new directory; no shares written: %w", err)
	}
	for _, s := range shares {
		if err := writeShareWithEncoding(root, fmt.Sprintf("share-%02d.txt", s.Index), s, words); err != nil {
			return fmt.Errorf("export incomplete; some shares may remain in the folder: %w", err)
		}
	}
	return nil
}

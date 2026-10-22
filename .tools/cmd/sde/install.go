//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// The pin. SDE_PAGE is the download page that serves SDE_URL.
const (
	SDE_VERSION = "10.13.1-2026-07-28"
	SDE_KIT     = "sde-external-" + SDE_VERSION + "-lin"
	SDE_ARCHIVE = SDE_KIT + ".tar.xz"
	SDE_URL     = "https://downloadmirror.intel.com/924984/" + SDE_ARCHIVE
	SDE_SHA256  = "94e97d623fec54385686e1e7ba65ebc9941748c05ee451423948334892bf2b50"
	SDE_PAGE    = "https://www.intel.com/content/www/us/en/download/684897/" +
		"intel-software-development-emulator.html"
	SDE_AGENT   = "tools-sde"
	SDE_TIMEOUT = 300 * time.Second
	PTRACE_PATH = "/proc/sys/kernel/yama/ptrace_scope"
	DIR_MODE    = 0o755
	EXEC_BIT    = 0o111
)

// _Paths is where this command keeps the pin: the archive, and the unpacked kit.
type _Paths struct {
	downloads string
	kit       string
}

// _Dir is the directory of this source file, so go run finds the kit beside it.
//
// Revisions:
//   - 2026-10-21 21:37: initial creation
func _Dir() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("sde source path is unknown")
	}

	dir := filepath.Dir(file)
	if !filepath.IsAbs(dir) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}

		dir = filepath.Join(
			cwd,
			dir,
		)
	}

	info, err := os.Stat(dir)
	if err != nil {
		return "", err
	}

	if !info.IsDir() {
		return "", fmt.Errorf(
			"sde path %s is not a directory",
			dir,
		)
	}

	return dir, nil
}

// _Install returns the sde program, after a download when the kit is absent.
//
// Revisions:
//   - 2026-10-21 21:37: initial creation
func _Install(paths *_Paths) (string, error) {
	found, err := _Binary(paths)
	if err != nil {
		return "", err
	}

	if found != "" {
		return found, nil
	}

	if err := os.MkdirAll(
		paths.downloads,
		DIR_MODE,
	); err != nil {
		return "", err
	}

	if err := os.MkdirAll(
		paths.kit,
		DIR_MODE,
	); err != nil {
		return "", err
	}

	archive := filepath.Join(
		paths.downloads,
		SDE_ARCHIVE,
	)
	if err := _Fetch(archive); err != nil {
		return "", err
	}

	if err := _Extract(
		archive,
		paths.kit,
	); err != nil {
		return "", err
	}

	found, err = _Binary(paths)
	if err != nil {
		return "", err
	}

	if found == "" {
		return "", fmt.Errorf("the kit unpacked and sde is not in it")
	}

	return found, nil
}

// _Binary is the sde program inside the unpacked kit, or an empty path when it
// is absent. An existing file with no execute bit is made executable.
//
// Revisions:
//   - 2026-10-21 21:37: initial creation
func _Binary(paths *_Paths) (string, error) {
	var (
		path = filepath.Join(
			paths.kit,
			SDE_KIT,
			"sde",
		)
		info, err = os.Stat(path)
	)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}

		return "", err
	}

	if info.IsDir() {
		return "", nil
	}

	if info.Mode()&EXEC_BIT == 0 {
		if chmodErr := os.Chmod(
			path,
			info.Mode()|EXEC_BIT,
		); chmodErr != nil {
			return "", chmodErr
		}
	}

	return path, nil
}

// _Fetch downloads the pin when the local archive is absent or the digest differs.
//
// Revisions:
//   - 2026-10-21 21:37: initial creation
func _Fetch(archive string) error {
	match, err := _Matches(archive)
	if err != nil {
		return err
	}

	if match {
		return nil
	}

	fmt.Fprintf(
		os.Stderr,
		"sde: download %s\n",
		SDE_URL,
	)

	return _Download(archive)
}

// _Matches reports whether archive exists and its SHA256 is the pin.
//
// Revisions:
//   - 2026-10-21 21:37: initial creation
func _Matches(archive string) (bool, error) {
	if _, err := os.Stat(archive); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}

		return false, err
	}

	got, err := _Sum(archive)
	if err != nil {
		return false, err
	}

	return got == SDE_SHA256, nil
}

// _Download writes the pin to archive. A failed write leaves no partial file.
//
// Revisions:
//   - 2026-10-21 21:37: initial creation
func _Download(archive string) error {
	body, err := _FetchBody()
	if err != nil {
		return err
	}

	err = _Store(
		archive,
		body,
	)
	closeErr := body.Close()

	if err != nil {
		return err
	}

	return closeErr
}

// _FetchBody is the response body of the pin. A status other than 200 closes
// the body and returns an error.
//
// Revisions:
//   - 2026-10-21 21:37: initial creation
func _FetchBody() (io.ReadCloser, error) {
	var (
		request, err = http.NewRequest(
			http.MethodGet,
			SDE_URL,
			nil,
		)
	)
	if err != nil {
		return nil, err
	}

	request.Header.Set(
		"User-Agent",
		SDE_AGENT,
	)

	var (
		client = &http.Client{
			Timeout: SDE_TIMEOUT,
		}
		response, doErr = client.Do(request)
	)
	if doErr != nil {
		return nil, fmt.Errorf(
			"download: %w",
			doErr,
		)
	}

	if response.StatusCode == http.StatusOK {
		return response.Body, nil
	}

	closeErr := response.Body.Close()
	if closeErr != nil {
		return nil, closeErr
	}

	return nil, fmt.Errorf(
		"download status %s, see %s",
		response.Status,
		SDE_PAGE,
	)
}

// _Store copies body to a partial file, checks the pin, and renames it.
//
// Revisions:
//   - 2026-10-21 21:37: initial creation
func _Store(
	archive string,
	body io.Reader,
) error {
	var (
		temporary      = archive + ".part"
		out, createErr = os.Create(temporary)
	)
	if createErr != nil {
		return createErr
	}

	var (
		_, copyErr = io.Copy(
			out,
			body,
		)
		closeErr = out.Close()
	)
	if copyErr != nil {
		return _Drop(
			temporary,
			copyErr,
		)
	}

	if closeErr != nil {
		return _Drop(
			temporary,
			closeErr,
		)
	}

	if err := _Check(temporary); err != nil {
		return _Drop(
			temporary,
			err,
		)
	}

	return os.Rename(
		temporary,
		archive,
	)
}

// _Drop removes path and returns err. A failed remove stays in the error.
//
// Revisions:
//   - 2026-10-21 21:37: initial creation
func _Drop(
	path string,
	err error,
) error {
	removeErr := os.Remove(path)
	if removeErr != nil {
		return errors.Join(
			err,
			removeErr,
		)
	}

	return err
}

// _Check refuses an archive whose SHA256 is not the pin.
//
// Revisions:
//   - 2026-10-21 21:37: initial creation
func _Check(archive string) error {
	got, err := _Sum(archive)
	if err != nil {
		return err
	}

	if got != SDE_SHA256 {
		return fmt.Errorf(
			"sha256 %s, want %s",
			got,
			SDE_SHA256,
		)
	}

	return nil
}

// _Sum is the SHA256 hex digest of path.
//
// Revisions:
//   - 2026-10-21 21:37: initial creation
func _Sum(path string) (string, error) {
	src, err := os.Open(path)
	if err != nil {
		return "", err
	}

	var (
		digest     = sha256.New()
		_, copyErr = io.Copy(
			digest,
			src,
		)
		closeErr = src.Close()
	)
	if copyErr != nil {
		return "", copyErr
	}

	if closeErr != nil {
		return "", closeErr
	}

	return hex.EncodeToString(digest.Sum(nil)), nil
}

// _Extract unpacks archive under root. A member that escapes root is refused.
// The standard library has no xz reader, so this runs the system tar.
//
// Revisions:
//   - 2026-10-21 21:37: initial creation
func _Extract(
	archive string,
	root string,
) error {
	fmt.Fprintf(
		os.Stderr,
		"sde: unpack %s\n",
		SDE_KIT,
	)

	names, err := _List(archive)
	if err != nil {
		return err
	}

	for _, name := range names {
		if _Inside(
			root,
			name,
		) {
			continue
		}

		return fmt.Errorf(
			"archive member escapes the kit directory: %s",
			name,
		)
	}

	cmd := exec.Command(
		"tar",
		"-xJf",
		archive,
		"-C",
		root,
	)
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf(
			"unpack: %w",
			err,
		)
	}

	return nil
}

// _List is the member names in archive.
//
// Revisions:
//   - 2026-10-21 21:37: initial creation
func _List(archive string) ([]string, error) {
	var (
		cmd = exec.Command(
			"tar",
			"-tJf",
			archive,
		)
		out, err = cmd.Output()
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list archive: %w",
			err,
		)
	}

	var (
		names []string
	)

	for line := range strings.SplitSeq(
		string(out),
		"\n",
	) {
		if line == "" {
			continue
		}

		names = append(
			names,
			line,
		)
	}

	return names, nil
}

// _Inside reports whether name, joined to root, stays inside root.
//
// Revisions:
//   - 2026-10-21 21:37: initial creation
func _Inside(
	root string,
	name string,
) bool {
	if name == "" || filepath.IsAbs(name) {
		return false
	}

	clean := filepath.Clean(name)
	if clean == ".." || strings.HasPrefix(
		clean,
		".."+string(filepath.Separator),
	) {
		return false
	}

	var (
		dest = filepath.Join(
			root,
			clean,
		)
		rel, err = filepath.Rel(
			root,
			dest,
		)
	)
	if err != nil {
		return false
	}

	if rel == ".." {
		return false
	}

	return !strings.HasPrefix(
		rel,
		".."+string(filepath.Separator),
	)
}

// _RequirePtrace stops when the kernel forbids the attach SDE uses.
//
// Revisions:
//   - 2026-10-21 21:37: initial creation
func _RequirePtrace() error {
	data, err := os.ReadFile(PTRACE_PATH)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return err
	}

	scope := strings.TrimSpace(string(data))
	if scope == "0" {
		return nil
	}

	return fmt.Errorf(
		"ptrace_scope is %s\nsde: run: echo 0 | sudo tee %s",
		scope,
		PTRACE_PATH,
	)
}

// _Exec replaces this process with sde. It returns only when the exec fails.
//
// Revisions:
//   - 2026-10-21 21:37: initial creation
func _Exec(
	binary string,
	args []string,
) error {
	argv := append(
		[]string{binary},
		args...,
	)

	return syscall.Exec(
		binary,
		argv,
		os.Environ(),
	)
}

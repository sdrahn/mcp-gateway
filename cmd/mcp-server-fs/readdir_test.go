package main

import (
	"errors"
	"io/fs"
	"strings"
	"syscall"
	"testing"
)

// fakeDir hands out its batches one ReadDir call at a time, as os.File
// does when examining an entry (fstatat, lstat) fails: the entries before it and
// the error, then the rest on the next call.
type fakeDir struct {
	batches [][]fs.DirEntry
	errs    []error
}

func (d *fakeDir) ReadDir(int) ([]fs.DirEntry, error) {
	if len(d.batches) == 0 {
		return nil, nil
	}
	b, err := d.batches[0], d.errs[0]
	d.batches, d.errs = d.batches[1:], d.errs[1:]
	return b, err
}

type named string

func (n named) Name() string             { return string(n) }
func (named) IsDir() bool                { return false }
func (named) Type() fs.FileMode          { return 0 }
func (named) Info() (fs.FileInfo, error) { return nil, errors.New("no info") }

func names(entries []fs.DirEntry) string {
	var out []string
	for _, e := range entries {
		out = append(out, "["+kind(e)+"] "+e.Name())
	}
	return strings.Join(out, " ")
}

func TestReadEntriesKeepsUnexamined(t *testing.T) {
	for _, op := range []string{"fstatat", "lstat"} {
		denied := &fs.PathError{Op: op, Path: "/home/dora/.cache", Err: syscall.EACCES}
		d := &fakeDir{
			batches: [][]fs.DirEntry{{named(".bashrc")}, {named("a.txt")}},
			errs:    []error{denied, nil},
		}
		entries, err := readEntries(d)
		if err != nil {
			t.Fatal(err)
		}
		if got := names(entries); got != "[FILE] .bashrc [?] .cache [FILE] a.txt" {
			t.Errorf("%s: entries: %s", op, got)
		}
	}
}

func TestReadEntriesOtherErrors(t *testing.T) {
	for _, err := range []error{
		&fs.PathError{Op: "readdirent", Path: "/home/dora", Err: syscall.EACCES},
		&fs.PathError{Op: "lstat", Path: "/home/dora/x", Err: syscall.EIO},
	} {
		d := &fakeDir{batches: [][]fs.DirEntry{{named("a")}}, errs: []error{err}}
		if _, got := readEntries(d); !errors.Is(got, err) {
			t.Errorf("%v: got %v", err, got)
		}
	}
}

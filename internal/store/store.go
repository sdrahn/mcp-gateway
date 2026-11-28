// Package store keeps the gateway's state that people reach, other than
// the principal it belongs to, in a shared store (docs/architecture.md,
// section 5.12.5, D24): grants, approvals, notices, reviews, sign-in
// tokens, the clients seen. A store holds collections of records, each a
// document with a name and a version that changes with every write;
// writes that name a version succeed only on it (compare-and-set), and a
// collection can be watched. The Kubernetes API is the store
// (Kubernetes, as Secrets); without one the gateway keeps its files in
// state_dir as before.
package store

import (
	"context"
	"errors"
)

// Errors of a collection's writes.
var (
	// ErrExists: a record of that name exists already.
	ErrExists = errors.New("store: record exists")
	// ErrNotFound: no record of that name.
	ErrNotFound = errors.New("store: no such record")
	// ErrConflict: the record's version is no longer the one named.
	ErrConflict = errors.New("store: record changed")
	// ErrExpired: a watch's version is too old; list again.
	ErrExpired = errors.New("store: version too old to watch from")
)

// Record is a record of a collection. Version is the store's, opaque.
type Record struct {
	Name    string
	Data    []byte
	Version string
}

// Event is a change of a collection: a record written (Deleted false)
// or deleted.
type Event struct {
	Record  Record
	Deleted bool
}

// Collection is a collection of records.
type Collection interface {
	// List returns the records and the collection's version, from which
	// Watch starts.
	List(ctx context.Context) ([]Record, string, error)
	// Create writes a new record (ErrExists if the name is taken).
	Create(ctx context.Context, name string, data []byte) (Record, error)
	// Update replaces r if its version is still r.Version (ErrConflict
	// otherwise, ErrNotFound if it is gone).
	Update(ctx context.Context, r Record) (Record, error)
	// Delete deletes the record of that name: if version is not empty,
	// only that version (ErrConflict otherwise). ErrNotFound if it is
	// gone.
	Delete(ctx context.Context, name, version string) error
	// Watch calls fn for each change after version, in order, and
	// returns when ctx ends (ctx.Err()), the watch breaks (an error,
	// ErrExpired if version is too old), or the store ends it (nil:
	// watch again from the last version seen, which fn's events carry
	// and bookmark reports).
	Watch(ctx context.Context, version string, fn func(Event), bookmark func(version string)) error
}

package store

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
)

// Key returns the key called name in c, of size bytes: made and stored
// at its first use, as the files in state_dir are (the sign-in tokens'
// key, the audit's). Two writers making it at once agree on the one that
// was stored first.
func Key(ctx context.Context, c Collection, name string, size int) ([]byte, error) {
	for range 3 {
		recs, _, err := c.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", name, err)
		}
		for _, r := range recs {
			if r.Name != name {
				continue
			}
			if len(r.Data) != size {
				return nil, fmt.Errorf("key %s: %d bytes, not %d", name, len(r.Data), size)
			}
			return r.Data, nil
		}
		key := make([]byte, size)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if _, err := c.Create(ctx, name, key); err == nil {
			return key, nil
		} else if !errors.Is(err, ErrExists) {
			return nil, fmt.Errorf("key %s: %w", name, err)
		}
		// Made meanwhile: read that one.
	}
	return nil, fmt.Errorf("key %s: not stored", name)
}

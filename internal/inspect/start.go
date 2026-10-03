package inspect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
)

// Start starts one instance of b for p with l, probes it and stops it.
func Start(ctx context.Context, l supervisor.Launcher, b *config.Backend, p principal.Principal) (*Result, error) {
	id := make([]byte, 8)
	_, _ = rand.Read(id) // never fails (crypto/rand)
	inst, err := l.Start(ctx, b, p, hex.EncodeToString(id))
	if err != nil {
		return nil, fmt.Errorf("starting: %w", err)
	}
	defer func() { _ = inst.Close() }()
	return Probe(ctx, inst)
}

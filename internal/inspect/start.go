package inspect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
)

// Start starts one instance of b for p with l, probes it and stops it. A
// server that exits on server/discover is started again and initialized.
func Start(ctx context.Context, l supervisor.Launcher, b *config.Backend, p principal.Principal) (*Result, error) {
	res, err := start(ctx, l, b, p, false)
	if errors.Is(err, ErrProbeEnded) {
		res, err = start(ctx, l, b, p, true)
	}
	return res, err
}

func start(ctx context.Context, l supervisor.Launcher, b *config.Backend, p principal.Principal, legacy bool) (*Result, error) {
	id := make([]byte, 8)
	_, _ = rand.Read(id) // never fails (crypto/rand)
	inst, err := l.Start(ctx, b, p, hex.EncodeToString(id))
	if err != nil {
		return nil, fmt.Errorf("starting: %w", err)
	}
	defer func() { _ = inst.Close() }()
	s, res, err := open(ctx, inst, legacy)
	if err != nil {
		return nil, err
	}
	s.Close()
	return res, nil
}

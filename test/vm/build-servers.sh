#!/bin/bash
# Builds the MCP servers that the setup packages (profiles/) are for, from
# their upstream sources at pinned versions, for the VM tests. Run on the
# distribution the VM runs (the zypp worker links libzypp); needs git, go,
# make, gcc, gcc-c++, cmake, systemd-devel, libzypp-devel, yaml-cpp-devel
# and the Boost test library.
#
# Usage: test/vm/build-servers.sh <output dir>
#
# The output dir is laid out like the root file system (usr/bin/...,
# usr/libexec/...), to be copied to / in the VM.
set -euo pipefail

# Pinned upstream versions (tags, or a commit where there is no tag yet).
SYSTEMD_MCP=v0.3.5     # https://github.com/openSUSE/systemd-mcp
FIREWALLD_MCP=v0.1.0   # https://github.com/janvhs/firewalld-mcp
CONNECT_NG=962ea948c42176f5f774aab2730c7d290bd0e30b # https://github.com/SUSE/connect-ng (suseconnect-mcp)
MCP_SERVER_ZYPP=0.1.2  # https://github.com/openSUSE/mcp-server-zypp
MCP_SERVER_SNAPPER=f0f09a0422868d9f7f0a9e81ec7fdf53226712fb # https://github.com/aschnell/mcp-server-snapper (0.3.0)

[ $# = 1 ] || {
	echo "usage: $0 <output dir>" >&2
	exit 2
}
out=$(realpath -m "$1")
mkdir -p "$out/usr/bin" "$out/usr/libexec/mcp-server-zypp"
src=$(mktemp -d)
trap 'rm -rf "$src"' EXIT

fetch() { # fetch <owner/repo> <dir> <revision>
	git clone -q "https://github.com/$1" "$src/$2"
	git -C "$src/$2" checkout -q "$3"
	echo "== $1 $3 ($(git -C "$src/$2" rev-parse --short HEAD))"
}

fetch openSUSE/systemd-mcp systemd-mcp "$SYSTEMD_MCP"
# cgo: the journal is read through libsystemd (sd-journal.h).
(cd "$src/systemd-mcp" && go build -trimpath -o "$out/usr/bin/systemd-mcp" .)

fetch janvhs/firewalld-mcp firewalld-mcp "$FIREWALLD_MCP"
(cd "$src/firewalld-mcp" && CGO_ENABLED=0 go build -trimpath -o "$out/usr/bin/firewalld-mcp" ./cmd/firewalld-mcp)

fetch SUSE/connect-ng connect-ng "$CONNECT_NG"
# The version is embedded from a file the Makefile writes.
(cd "$src/connect-ng" && make -s internal/connect/version.txt && CGO_ENABLED=0 go build -trimpath -o "$out/usr/bin/suseconnect-mcp" ./cmd/suseconnect-mcp)

fetch openSUSE/mcp-server-zypp mcp-server-zypp "$MCP_SERVER_ZYPP"
# The C++ worker with cmake, the Go proxy separately (as the upstream spec
# does), told where the worker is.
cmake -S "$src/mcp-server-zypp" -B "$src/zypp-build" -DBUILD_GO_PROXY=OFF -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$src/zypp-build" --target zypp-mcp-tool -j "$(nproc)"
install -m 0755 "$src/zypp-build/worker/zypp-mcp-tool" "$out/usr/libexec/mcp-server-zypp/"
(cd "$src/mcp-server-zypp/proxy" && CGO_ENABLED=0 go build -trimpath \
	-ldflags "-X 'github.com/openSUSE/mcp-server-zypp/internal/config.DefaultWorkerDir=/usr/libexec/mcp-server-zypp'" \
	-o "$out/usr/bin/mcp-server-zypp" ./cmd/mcp-server-zypp)

fetch aschnell/mcp-server-snapper mcp-server-snapper "$MCP_SERVER_SNAPPER"
(cd "$src/mcp-server-snapper" && CGO_ENABLED=0 go build -mod=vendor -trimpath \
	-ldflags "-X main.Version=$(cat VERSION)" -o "$out/usr/bin/mcp-server-snapper" ./src)

# mcp-gateway review on the real sources (roadmap step 11, stage 3): the
# reports go to the job log; the helpers systemd-mcp is known to run must
# be found.
repo=$(cd "$(dirname "$0")/../.." && pwd)
(cd "$repo" && go build -buildvcs=false -o "$src/mcp-gateway" ./cmd/mcp-gateway)
review() { # review <name> <dir> [--main PKG]
	local name=$1 dir=$2
	shift 2
	echo "== review $name"
	"$src/mcp-gateway" review --source "$dir" "$@" | tee "$src/review-$name.txt"
}
review systemd-mcp "$src/systemd-mcp" --main .
review firewalld-mcp "$src/firewalld-mcp" --main ./cmd/firewalld-mcp
review suseconnect-mcp "$src/connect-ng" --main ./cmd/suseconnect-mcp
review mcp-server-zypp "$src/mcp-server-zypp"
review mcp-server-snapper "$src/mcp-server-snapper" --main ./src
for p in rpm man getfacl; do
	grep -q "^  $p  " "$src/review-systemd-mcp.txt" || {
		echo "review: systemd-mcp runs $p, not found" >&2
		exit 1
	}
done

ls -lR "$out"

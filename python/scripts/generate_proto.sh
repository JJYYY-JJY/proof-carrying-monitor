#!/usr/bin/env bash
# Generate Python protobuf/gRPC code from .proto files.
#
# Usage:
#   cd <repo-root>/python
#   bash scripts/generate_proto.sh
#
# Prerequisites:
#   pip install grpcio-tools

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROTO_DIR="$REPO_ROOT/proto"
OUT_DIR="$SCRIPT_DIR/../pcm_proto/v1"

mkdir -p "$OUT_DIR"

python -m grpc_tools.protoc \
    -I "$PROTO_DIR" \
    --python_out="$OUT_DIR" \
    --pyi_out="$OUT_DIR" \
    --grpc_python_out="$OUT_DIR" \
    "$PROTO_DIR/pcm/v1/types.proto" \
    "$PROTO_DIR/pcm/v1/services.proto"

echo "Python protobuf stubs generated in $OUT_DIR"

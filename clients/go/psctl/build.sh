#!/bin/bash
set -uo pipefail
cd "$(dirname "$0")"
export GOFLAGS=-mod=mod
echo "== go vet =="
go vet ./... && echo "vet OK" || echo "vet FAILED"
echo "== build linux =="
go build -o psctl . && echo "OK-linux" || { echo "LINUX BUILD FAILED"; exit 1; }
echo "== build windows =="
GOOS=windows GOARCH=amd64 go build -o psctl.exe . && echo "OK-windows" || { echo "WIN BUILD FAILED"; exit 1; }
echo "== artifacts =="
ls -la psctl psctl.exe
file psctl.exe 2>/dev/null || true

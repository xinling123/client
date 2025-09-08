#!/bin/bash

# 创建输出目录
mkdir -p bin

echo "Building server monitor client for multiple platforms..."

# Linux x86_64 (静态链接)
echo "Building for Linux x86_64..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags '-extldflags "-static" -s -w' -o bin/server-monitor-linux-amd64 main.go

# Linux ARM64 (静态链接)
echo "Building for Linux ARM64..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -a -ldflags '-extldflags "-static" -s -w' -o bin/server-monitor-linux-arm64 main.go

# Linux 386 (静态链接)
echo "Building for Linux 386..."
CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -a -ldflags '-extldflags "-static" -s -w' -o bin/server-monitor-linux-386 main.go

# Windows x86_64
echo "Building for Windows x86_64..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags '-s -w' -o bin/server-monitor-windows-amd64.exe main.go

# Windows 386
echo "Building for Windows 386..."
CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -ldflags '-s -w' -o bin/server-monitor-windows-386.exe main.go

# macOS x86_64
echo "Building for macOS x86_64..."
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags '-s -w' -o bin/server-monitor-darwin-amd64 main.go

# macOS ARM64 (Apple Silicon)
echo "Building for macOS ARM64..."
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags '-s -w' -o bin/server-monitor-darwin-arm64 main.go

# FreeBSD x86_64
echo "Building for FreeBSD x86_64..."
CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -ldflags '-s -w' -o bin/server-monitor-freebsd-amd64 main.go

echo "Build completed! Binaries are in the bin/ directory:"
ls -la bin/

echo ""
echo "File sizes:"
du -h bin/*

echo ""
echo "Usage example:"
echo "./bin/server-monitor-linux-amd64 URL=https://your-server.com/api/config UUID=your-uuid Client_ID=your-client-id"

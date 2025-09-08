@echo off
setlocal

REM 创建输出目录
if not exist bin mkdir bin

echo Building server monitor client for multiple platforms...

REM Linux x86_64 (静态链接)
echo Building for Linux x86_64...
set CGO_ENABLED=0
set GOOS=linux
set GOARCH=amd64
go build -a -ldflags "-extldflags \"-static\" -s -w" -o bin/server-monitor-linux-amd64 main.go

REM Linux ARM64 (静态链接)
echo Building for Linux ARM64...
set CGO_ENABLED=0
set GOOS=linux
set GOARCH=arm64
go build -a -ldflags "-extldflags \"-static\" -s -w" -o bin/server-monitor-linux-arm64 main.go

REM Linux 386 (静态链接)
echo Building for Linux 386...
set CGO_ENABLED=0
set GOOS=linux
set GOARCH=386
go build -a -ldflags "-extldflags \"-static\" -s -w" -o bin/server-monitor-linux-386 main.go

REM Windows x86_64
echo Building for Windows x86_64...
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
go build -ldflags "-s -w" -o bin/server-monitor-windows-amd64.exe main.go

REM Windows 386
echo Building for Windows 386...
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=386
go build -ldflags "-s -w" -o bin/server-monitor-windows-386.exe main.go

REM macOS x86_64
echo Building for macOS x86_64...
set CGO_ENABLED=0
set GOOS=darwin
set GOARCH=amd64
go build -ldflags "-s -w" -o bin/server-monitor-darwin-amd64 main.go

REM macOS ARM64 (Apple Silicon)
echo Building for macOS ARM64...
set CGO_ENABLED=0
set GOOS=darwin
set GOARCH=arm64
go build -ldflags "-s -w" -o bin/server-monitor-darwin-arm64 main.go

REM FreeBSD x86_64
echo Building for FreeBSD x86_64...
set CGO_ENABLED=0
set GOOS=freebsd
set GOARCH=amd64
go build -ldflags "-s -w" -o bin/server-monitor-freebsd-amd64 main.go

echo.
echo Build completed! Binaries are in the bin\ directory:
dir bin\

echo.
echo Usage example:
echo bin\server-monitor-windows-amd64.exe URL=https://your-server.com/api/config UUID=your-uuid Client_ID=your-client-id

endlocal

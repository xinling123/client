# Server Monitor Client (Go Version)

这是原Python版本服务器监控客户端的Go重写版本，专为跨平台兼容性而设计，支持Linux (x86_64/ARM64)、Windows和macOS。

## 功能特性

- **系统监控**: CPU使用率、内存、磁盘、网络流量、系统负载等
- **网络监控**: 多线路ping测试（联通、电信、移动）
- **Docker监控**: 容器状态、资源使用情况
- **跨平台支持**: Linux、Windows、macOS，支持x86_64和ARM64架构
- **纯静态二进制**: 使用CGO_ENABLED=0编译，无需系统依赖
- **日志轮转**: 自动日志文件管理
- **实时数据**: 每秒收集和上报系统数据

## 构建说明

### 1. 安装依赖
```bash
go mod download
```

### 2. 跨平台编译

#### Linux x86_64 (静态链接)
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags '-extldflags "-static"' -o server-monitor-linux-amd64 main.go
```

#### Linux ARM64 (静态链接)
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -a -ldflags '-extldflags "-static"' -o server-monitor-linux-arm64 main.go
```

#### Windows x86_64
```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o server-monitor-windows-amd64.exe main.go
```

#### macOS x86_64
```bash
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o server-monitor-darwin-amd64 main.go
```

#### macOS ARM64 (Apple Silicon)
```bash
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o server-monitor-darwin-arm64 main.go
```

### 3. 一键构建所有平台
```bash
#!/bin/bash
# build-all.sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags '-extldflags "-static"' -o bin/server-monitor-linux-amd64 main.go
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -a -ldflags '-extldflags "-static"' -o bin/server-monitor-linux-arm64 main.go
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/server-monitor-windows-amd64.exe main.go
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o bin/server-monitor-darwin-amd64 main.go
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o bin/server-monitor-darwin-arm64 main.go
```

## 使用方法

### 命令行参数
```bash
./server-monitor-linux-amd64 URL=<server_url> UUID=<uuid> Client_ID=<client_id>
```

### 参数说明
- `URL`: 服务器配置获取地址
- `UUID`: 服务器分配的唯一标识符
- `Client_ID`: 客户端认证ID

### 示例
```bash
./server-monitor-linux-amd64 URL=https://your-server.com/api/config UUID=your-uuid Client_ID=your-client-id
```

## 系统要求

### 最低内核版本支持
- **Linux**: 内核版本 >= 2.6.23 (glibc >= 2.6)
- **Windows**: Windows 7 / Server 2008 R2 及以上
- **macOS**: macOS 10.12 及以上

### 权限要求
- Linux: 建议以root权限运行以获取完整的系统信息
- Windows: 建议以管理员权限运行
- macOS: 普通用户权限即可

## 兼容性说明

### 静态链接优势
通过设置 `CGO_ENABLED=0`，编译出的二进制文件：
- 不依赖系统的glibc版本
- 不需要安装额外的C库
- 可以在更老的Linux发行版上运行
- 文件体积较大但兼容性最佳

### Docker监控
- 自动检测Docker是否安装
- 如果Docker不可用，该功能会被跳过，不影响其他监控功能
- 支持Docker API版本协商

### 网络监控
- 自动跳过虚拟网络接口（lo、docker、veth等）
- 支持IPv4和IPv6双栈
- 自动DNS解析和IP地址获取

## 日志文件

### 日志位置
- **Linux**: `/var/log/server_watch.log`
- **Windows**: `./server_watch.log`（程序目录下）
- **macOS**: `/var/log/server_watch.log`

### 日志轮转
- 最大文件大小: 20MB
- 保留备份数: 5个
- 自动压缩旧日志

## 故障排除

### 1. 权限问题
如果遇到权限错误，尝试：
```bash
# Linux/macOS
sudo ./server-monitor-linux-amd64 URL=... UUID=... Client_ID=...

# Windows (以管理员身份运行PowerShell)
.\server-monitor-windows-amd64.exe URL=... UUID=... Client_ID=...
```

### 2. 网络连接问题
检查防火墙设置，确保可以访问：
- 服务器配置URL
- IP地址检测服务 (ipw.cn, ipwho.is)
- ping目标服务器

### 3. Docker监控不工作
确保：
- Docker服务正在运行
- 当前用户有权限访问Docker socket
- Docker API版本兼容

### 4. 在老系统上运行
如果在非常老的Linux系统上运行遇到问题：
```bash
# 检查内核版本
uname -r

# 检查glibc版本
ldd --version
```

静态编译的二进制应该在大多数Linux系统上工作，如果仍有问题，可以尝试在目标系统上直接编译。

## 性能优化

### 内存使用
- 典型内存占用: 10-20MB
- Docker监控会增加内存使用
- 使用goroutine池避免过多线程创建

### CPU使用
- 正常情况下CPU使用率 < 1%
- ping测试和数据收集是主要的CPU消耗

### 网络带宽
- 每秒发送约1-2KB数据到服务器
- IP地址检测每6小时执行一次

## 与Python版本的差异

1. **依赖管理**: Go版本无需安装Python和pip包
2. **性能**: Go版本内存占用更小，启动更快
3. **兼容性**: 静态编译提供更好的跨系统兼容性
4. **部署**: 单个二进制文件，无需配置Python环境

## 开发说明

如需修改代码，请注意：
- 保持CGO_ENABLED=0以确保静态链接
- 使用Go标准库和纯Go第三方库
- 测试多平台兼容性
- 保持与原Python版本的协议兼容性

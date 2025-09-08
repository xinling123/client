#!/bin/bash

# Server Monitor Client Service Installation Script

SERVICE_NAME="server-monitor"
SERVICE_USER="root"
INSTALL_DIR="/opt/server-monitor"
BINARY_NAME="server-monitor-linux-amd64"

# 检查是否以root权限运行
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root (use sudo)"
    exit 1
fi

# 检查参数
if [ $# -lt 3 ]; then
    echo "Usage: $0 <URL> <UUID> <CLIENT_ID> [binary_name]"
    echo "Example: $0 https://your-server.com/api/config your-uuid your-client-id"
    echo "Optional: specify binary name (default: server-monitor-linux-amd64)"
    exit 1
fi

URL="$1"
UUID="$2"
CLIENT_ID="$3"
if [ $# -ge 4 ]; then
    BINARY_NAME="$4"
fi

echo "Installing Server Monitor Client as systemd service..."

# 创建安装目录
mkdir -p "$INSTALL_DIR"

# 检查二进制文件是否存在
if [ ! -f "bin/$BINARY_NAME" ]; then
    echo "Error: Binary file bin/$BINARY_NAME not found!"
    echo "Please run the build script first: ./build.sh"
    exit 1
fi

# 复制二进制文件
cp "bin/$BINARY_NAME" "$INSTALL_DIR/server-monitor"
chmod +x "$INSTALL_DIR/server-monitor"

# 创建日志目录
mkdir -p /var/log

# 创建systemd服务文件
cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=Server Monitor Client
After=network.target
Wants=network.target

[Service]
Type=simple
User=$SERVICE_USER
ExecStart=$INSTALL_DIR/server-monitor URL=$URL UUID=$UUID Client_ID=$CLIENT_ID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# 资源限制
LimitNOFILE=65536
LimitNPROC=32768

# 安全设置
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/log /tmp
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# 重新加载systemd配置
systemctl daemon-reload

# 启用服务
systemctl enable "$SERVICE_NAME"

echo "Service installed successfully!"
echo ""
echo "To start the service:"
echo "  sudo systemctl start $SERVICE_NAME"
echo ""
echo "To check service status:"
echo "  sudo systemctl status $SERVICE_NAME"
echo ""
echo "To view logs:"
echo "  sudo journalctl -u $SERVICE_NAME -f"
echo ""
echo "To stop the service:"
echo "  sudo systemctl stop $SERVICE_NAME"
echo ""
echo "To uninstall the service:"
echo "  sudo systemctl stop $SERVICE_NAME"
echo "  sudo systemctl disable $SERVICE_NAME"
echo "  sudo rm /etc/systemd/system/$SERVICE_NAME.service"
echo "  sudo rm -rf $INSTALL_DIR"
echo "  sudo systemctl daemon-reload"

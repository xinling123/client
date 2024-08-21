#!/bin/bash

# 检查是否提供了 UUID
if [ -z "$1" ]; then
    echo "Usage: $0 <UUID>"
    exit 1
fi

UUID=$1
SERVICE_NAME="myclient.service"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"

# 创建 systemd 服务单元文件
echo "Creating systemd service file at $SERVICE_PATH..."

sudo bash -c "cat > $SERVICE_PATH" <<EOL
[Unit]
Description=My Client Service
After=network.target

[Service]
ExecStart=/root/client uuid=$UUID
Restart=always

[Install]
WantedBy=multi-user.target
EOL

# 重新加载 systemd 守护进程
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

# 启动服务
echo "Starting $SERVICE_NAME..."
sudo systemctl start $SERVICE_NAME

# 设置服务为开机自动启动
echo "Enabling $SERVICE_NAME to start on boot..."
sudo systemctl enable $SERVICE_NAME

echo "Service $SERVICE_NAME has been created and started with UUID=$UUID."

#!/bin/bash

# 检查是否提供了 UUID
if [ -z "$1" ]; then
    echo "Usage: $0 <UUID>"
    exit 1
fi

UUID=$1
SERVICE_NAME="myclient.service"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"

# 检查服务是否已经存在并运行
if systemctl is-active --quiet $SERVICE_NAME; then
    echo "$SERVICE_NAME 正在运行，只需重启服务..."
    sudo systemctl stop $SERVICE_NAME
    # 下载或更新 client 文件
    wget -N --no-check-certificate --inet4-only "https://raw.githubusercontent.com/xinling123/client/refs/heads/main/client" && chmod +x client
    sudo systemctl start $SERVICE_NAME
else
    echo "创建 systemd 服务文件在 $SERVICE_PATH..."

# 下载或更新 client 文件
wget -N --no-check-certificate --inet4-only "https://raw.githubusercontent.com/xinling123/client/refs/heads/main/client" && chmod +x client

    # 创建 systemd 服务单元文件
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
    echo "重新加载 systemd 守护进程..."
    sudo systemctl daemon-reload

    # 启动服务
    echo "启动 $SERVICE_NAME..."
    sudo systemctl start $SERVICE_NAME

    # 设置服务为开机自动启动
    echo "设置 $SERVICE_NAME 开机自动启动..."
    sudo systemctl enable $SERVICE_NAME
fi

echo "服务 $SERVICE_NAME 已更新并运行，UUID=$UUID."

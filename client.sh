#!/bin/bash

ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
echo "设置时区为 Asia/Shanghai..."

# 检查是否安装 NTP 服务（使用 chrony 或 ntp）
if ! command -v chronyd >/dev/null 2>&1 && ! command -v ntpd >/dev/null 2>&1; then
    echo "未检测到 NTP 服务，安装 chrony..."
    apt update && apt install -y chrony
else
    echo "NTP 服务已安装。"
fi

# 启用 NTP 时间同步
echo "启用 NTP 时间同步..."
timedatectl set-ntp true

# 检查 NTP 同步状态
NTP_STATUS=$(timedatectl show --property=NTP | cut -d= -f2)
if [[ "$NTP_STATUS" == "yes" ]]; then
    echo "NTP 时间同步已启用。"
else
    echo "NTP 时间同步启用失败，请检查 NTP 配置。"
    exit 1
fi

# 检查是否提供了 UUID, SERVER 和 PORT
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Usage: $0 <UUID> <SERVER> <PORT>"
    exit 1
fi

UUID=$1
SERVER=$2
PORT=$3
SERVICE_NAME="myclient.service"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"

# 检查服务是否已经存在
if systemctl list-units --full -all | grep -Fq "$SERVICE_NAME"; then
    echo "$SERVICE_NAME 已存在，删除旧的服务文件和服务..."
    systemctl stop $SERVICE_NAME # 停止服务
    systemctl disable $SERVICE_NAME # 禁用开机自启动
    rm -f $SERVICE_PATH # 删除服务文件
    systemctl daemon-reload # 重新加载 systemd 守护进程
fi

echo "创建 systemd 服务文件在 $SERVICE_PATH..."

# 下载或更新 client 文件
wget -N --no-check-certificate --inet4-only "https://raw.githubusercontent.com/xinling123/client/refs/heads/main/client" && chmod +x client

# 创建 systemd 服务单元文件
bash -c "cat > $SERVICE_PATH" <<EOL
[Unit]
Description=My Client Service
After=network.target

[Service]
ExecStart=/root/client UUID=$UUID SERVER=$SERVER PORT=$PORT
Restart=always

[Install]
WantedBy=multi-user.target
EOL

# 重新加载 systemd 守护进程
echo "重新加载 systemd 守护进程..."
systemctl daemon-reload

# 启动服务
echo "启动 $SERVICE_NAME..."
systemctl start $SERVICE_NAME

# 设置服务为开机自动启动
echo "设置 $SERVICE_NAME 开机自动启动..."
systemctl enable $SERVICE_NAME

echo "服务 $SERVICE_NAME 已更新并运行，UUID=$UUID, SERVER=$SERVER, PORT=$PORT."

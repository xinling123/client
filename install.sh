#!/bin/bash


# 检查是否提供了 UUID, SERVER 和 PORT
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Usage: $0 <UUID> <URL> <Client_ID>"
    exit 1
fi


UUID=$1
URL="https://$2/api/v1/client/get"
Client_ID=$3
SERVICE_NAME="serverwatch.service"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"


# 检查服务是否已经存在
if systemctl list-units --full -all | grep -Fq "$SERVICE_NAME"; then
    echo "$SERVICE_NAME 已存在，删除旧的服务文件和服务..."
    systemctl stop $SERVICE_NAME # 停止服务
    systemctl disable $SERVICE_NAME # 禁用开机自启动
    rm -f $SERVICE_PATH # 删除服务文件
    systemctl daemon-reload # 重新加载 systemd 守护进程
fi


echo "创建 systemd 服务"

# 使用 curl 获取 IP 地址（静默模式）
ip=$(curl -s test.ipw.cn)
if [ -z "$ip" ]; then
    echo "错误：无法获取 IP 地址。" >&2
    exit 1
fi

if [[ "$ip" == *:* ]]; then
    echo "IPv6"
    wget -N --no-check-certificate --inet6-only "https://raw.githubusercontent.com/xinling123/client/refs/heads/main/client" + " >/dev/null 2>&1" && chmod +x client
else
    wget -N --no-check-certificate --inet4-only "https://raw.githubusercontent.com/xinling123/client/refs/heads/main/client" + " >/dev/null 2>&1" && chmod +x client
fi

# 创建 systemd 服务单元文件
bash -c "cat > $SERVICE_PATH" <<EOL
[Unit]
Description=My Client Service
After=network.target

[Service]
ExecStart=/root/client UUID=$UUID URL=$URL Client_ID=$Client_ID
Restart=always

[Install]
WantedBy=multi-user.target
EOL

# 重新加载 systemd 守护进程
# echo "重新加载 systemd 守护进程..."
systemctl daemon-reload

# 启动服务
# echo "启动 $SERVICE_NAME..."
systemctl start $SERVICE_NAME


# 设置服务为开机自动启动
# echo "设置 $SERVICE_NAME 开机自动启动..."
systemctl enable $SERVICE_NAME

echo "启动成功"




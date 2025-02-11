#!/usr/bin/env python3
# coding: utf-8
# Update by : https://github.com/cppla/ServerStatus, Update date: 20220530
# 依赖于psutil跨平台库
# 版本：1.0.3, 支持Python版本：2.7 to 3.10
# 支持操作系统： Linux, Windows, OSX, Sun Solaris, FreeBSD, OpenBSD and NetBSD, both 32-bit and 64-bit architectures
# ONLINE_PACKET_HISTORY_LEN， 探测间隔120s，记录24小时在线率（720）；探测时间300s，记录24小时（288）；探测间隔60s，记录7天（10080）
# 说明: 默认情况下修改server和user就可以了。丢包率监测方向可以自定义，例如：CU = "www.facebook.com"。

import requests
import ast
import socket
import timeit
import select
import os
import json
import errno
import psutil
import platform
import threading
from datetime import datetime
import docker
import time
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

if sys.version_info.major == 3:
    from queue import Queue
elif sys.version_info.major == 2:
    from Queue import Queue

import logging
from logging.handlers import RotatingFileHandler

# Configure logging
log_file_path = '/root/server_watch.log'
max_log_size = 20 * 1024 * 1024  # 100 MB
backup_count = 5  # Number of backup files to keep

# Create a rotating file handler
handler = RotatingFileHandler(log_file_path, maxBytes=max_log_size, backupCount=backup_count)
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(handler)

CU = "cu.tz.cloudcpp.com"  # 联通
CT = "ct.tz.cloudcpp.com"  # 电信
CM = "cm.tz.cloudcpp.com"  # 移动
CU_PROBEPORT = 80
CT_PROBEPORT = 80
CM_PROBEPORT = 80
# 共享配置和锁
ping_configs = {
    '10010': {'host': CU, 'port': CU_PROBEPORT, 'name': ""},
    '189': {'host': CT, 'port': CT_PROBEPORT, 'name': ""},
    '10086': {'host': CM, 'port': CM_PROBEPORT, 'name': ""},
}
ping_config_lock = Lock()
PROBE_PROTOCOL_PREFER = "ipv4"  # ipv4, ipv6
PING_PACKET_HISTORY_LEN = 100
INTERVAL = 1

docker_dict = {}
previous_network_stats = {}
threading_start = False

lostRate = {
    '10010': 0.0,
    '189': 0.0,
    '10086': 0.0
}
pingTime = {
    '10010': 0,
    '189': 0,
    '10086': 0
}
netSpeed = {
    'netrx': 0.0,
    'nettx': 0.0,
    'clock': 0.0,
    'diff': 0.0,
    'avgrx': 0,
    'avgtx': 0
}
diskIO = {
    'read': 0,
    'write': 0
}


def get_cpu_usage(interval=1):
    # Get CPU usage for each core and calculate the average
    cpu_percentages = psutil.cpu_percent(interval=1, percpu=True)
    return cpu_percentages


def get_server_ip(url, ipv4, ipv6):
    try:
        res = requests.get(url).text
        lst = ast.literal_eval(res)
        logger.info(lst)
        server_ipv4 = lst[0]
        server_ipv6 = lst[1]
        server_port = lst[2]
    except Exception as e:
        return None, None
    if ipv4:
        return server_ipv4, server_port
    elif ipv6:
        return server_ipv6, server_port
    else:
        return None, None


# 获取服务器ip地址
def get_client_ip():
    country_code = ""
    emoji = ""
    priority = ""
    ipv4 = ""
    ipv6 = ""
    try:
        header = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0"
        }
        priority = requests.post('https://test.ipw.cn', headers=header).text
        res = requests.get(f'http://ipwho.is/{priority}')
        js = res.json()
        country_code = js.get('country_code')
        emoji = js.get('flag')
    except Exception as e:
        pass
    try:
        ipv4 = requests.get('https://4.ipw.cn/').text
    except Exception as e:
        pass
    try:
        ipv6 = requests.get('https://6.ipw.cn/').text
    except Exception as e:
        pass
    logger.info(f"{priority}, {country_code}, {emoji}, {ipv4}, {ipv6}")
    return priority, country_code, emoji, ipv4, ipv6


# 获取cpu负载
def get_load_average():
    return psutil.getloadavg()


# 获取cpu型号
def get_cpu_model():
    with open("/proc/cpuinfo") as f:
        for line in f:
            if "model name" in line:
                return line.split(":")[1].strip()


# 获取系统版本
def get_system_version():
    return platform.platform()


# 获取系统运行时间
def get_uptime():
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    return boot_time.strftime("%Y/%m/%d %H:%M:%S")


# 获取内存大小
def get_memory():
    mem = psutil.virtual_memory()
    used_memory = mem.total - mem.available
    return mem.total, used_memory


# 获取共享内存大小
def get_swap():
    mem = psutil.swap_memory()
    return mem.total, mem.used


# 获取磁盘空间大小
def get_disk():
    if "darwin" in sys.platform:
        return psutil.disk_usage("/").total, (psutil.disk_usage("/").total - psutil.disk_usage("/").free)
    else:
        valid_fs = ["ext4", "ext3", "ext2", "reiserfs", "jfs", "btrfs", "fuseblk", "zfs", "simfs", "ntfs", "fat32",
                    "exfat", "xfs"]
        disks = dict()
        size = 0
        used = 0
        for disk in psutil.disk_partitions():
            if not disk.device in disks and disk.fstype.lower() in valid_fs:
                disks[disk.device] = disk.mountpoint
        for disk in disks.values():
            usage = psutil.disk_usage(disk)
            size += usage.total
            used += usage.used
        return size, used


# 获取网络总上传下载大小
def get_network():
    network_in = 0
    network_out = 0
    net = psutil.net_io_counters(pernic=True)
    for k, v in net.items():
        if 'lo' in k or 'tun' in k \
                or 'docker' in k or 'veth' in k \
                or 'br-' in k or 'vmbr' in k \
                or 'vnet' in k or 'kube' in k:
            continue
        else:
            network_in += v[1]
            network_out += v[0]
    return network_in, network_out


# 获取tcp、udp、进程数、线程数
def tupd():
    '''
    获取TCP连接数、UDP连接数、进程数和线程数，用于监控DDoS攻击，然后发送警告
    :return: 返回TCP连接数、UDP连接数、进程数和线程数
    '''
    try:
        if sys.platform.startswith("linux") is True:
            t = int(os.popen('ss -t|wc -l').read()[:-1]) - 1
            u = int(os.popen('ss -u|wc -l').read()[:-1]) - 1
            p = int(os.popen('ps -ef|wc -l').read()[:-1]) - 2
            d = int(os.popen('ps -eLf|wc -l').read()[:-1]) - 2
        elif sys.platform.startswith("darwin") is True:
            t = int(os.popen('lsof -nP -iTCP  | wc -l').read()[:-1]) - 1
            u = int(os.popen('lsof -nP -iUDP  | wc -l').read()[:-1]) - 1
            p = len(psutil.pids())
            d = 0
            for k in psutil.pids():
                try:
                    d += psutil.Process(k).num_threads()
                except:
                    pass

        elif sys.platform.startswith("win") is True:
            t = int(os.popen('netstat -an|find "TCP" /c').read()[:-1]) - 1
            u = int(os.popen('netstat -an|find "UDP" /c').read()[:-1]) - 1
            p = len(psutil.pids())
            # if you find cpu is high, please set d=0
            d = sum([psutil.Process(k).num_threads() for k in psutil.pids()])
        else:
            t, u, p, d = 0, 0, 0, 0
        return t, u, p, d
    except:
        return 0, 0, 0, 0


def _ping_thread(mark):
    lostPacket = 0
    packet_queue = Queue(maxsize=PING_PACKET_HISTORY_LEN)
    with ping_config_lock:
        config = ping_configs.get(mark, {})
        host = config.get('host', '')
        port = config.get('port', 0)
    logger.info(f"ping {host}:{port} (Mark: {mark})")
    while True:
        # flush dns, every time.
        try:
            IP = host
            if host.count(':') < 1:  # if not plain ipv6 address, means ipv4 address or hostname
                try:
                    if PROBE_PROTOCOL_PREFER == 'ipv4':
                        IP = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
                    else:
                        IP = socket.getaddrinfo(host, None, socket.AF_INET6)[0][4][0]
                except Exception:
                    pass

            if packet_queue.full():
                if packet_queue.get() == 0:
                    lostPacket -= 1
            try:
                b = timeit.default_timer()
                socket.create_connection((IP, port), timeout=1).close()
                pingTime[mark] = int((timeit.default_timer() - b) * 1000)
                packet_queue.put(1)
            except socket.error as error:
                if error.errno == errno.ECONNREFUSED:
                    pingTime[mark] = int((timeit.default_timer() - b) * 1000)
                    packet_queue.put(1)
                # elif error.errno == errno.ETIMEDOUT:
                else:
                    lostPacket += 1
                    packet_queue.put(0)

            if packet_queue.qsize() > 30:
                lostRate[mark] = float(lostPacket) / packet_queue.qsize()
            time.sleep(2)
        except Exception as e:
            logger.error(f'_ping_thread error occurred123: {e}')


# 获取网络上传下载速度
def _net_speed():
    while True:
        avgrx = 0
        avgtx = 0
        for name, stats in psutil.net_io_counters(pernic=True).items():
            if "lo" in name or "tun" in name \
                    or "docker" in name or "veth" in name \
                    or "br-" in name or "vmbr" in name \
                    or "vnet" in name or "kube" in name:
                continue
            avgrx += stats.bytes_recv
            avgtx += stats.bytes_sent
        now_clock = time.time()
        netSpeed["diff"] = now_clock - netSpeed["clock"]
        netSpeed["clock"] = now_clock
        netSpeed["netrx"] = int((avgrx - netSpeed["avgrx"]) / netSpeed["diff"])
        netSpeed["nettx"] = int((avgtx - netSpeed["avgtx"]) / netSpeed["diff"])
        netSpeed["avgrx"] = avgrx
        netSpeed["avgtx"] = avgtx
        time.sleep(INTERVAL)


# 获取磁盘读取写入速度
def _disk_io():
    """
    the code is by: https://github.com/giampaolo/psutil/blob/master/scripts/iotop.py
    good luck for opensource! modify: cpp.la
    Calculate IO usage by comparing IO statics before and
        after the interval.
        Return a tuple including all currently running processes
        sorted by IO activity and total disks I/O activity.
    磁盘IO：因为IOPS原因，SSD和HDD、包括RAID卡，ZFS等。IO对性能的影响还需要结合自身服务器情况来判断。
    比如我这里是机械硬盘，大量做随机小文件读写，那么很低的读写也就能造成硬盘长时间的等待。
    如果这里做连续性IO，那么普通机械硬盘写入到100Mb/s，那么也能造成硬盘长时间的等待。
    磁盘读写有误差：4k，8k ，https://stackoverflow.com/questions/34413926/psutil-vs-dd-monitoring-disk-i-o
    macos/win，暂不处理。
    """
    if "darwin" in sys.platform or "win" in sys.platform:
        diskIO["read"] = 0
        diskIO["write"] = 0
    else:
        while True:
            # first get a list of all processes and disk io counters
            procs = [p for p in psutil.process_iter()]
            for p in procs[:]:
                try:
                    p._before = p.io_counters()
                except psutil.Error:
                    procs.remove(p)
                    continue
            disks_before = psutil.disk_io_counters()

            # sleep some time, only when INTERVAL==1 , io read/write per_sec.
            # when INTERVAL > 1, io read/write per_INTERVAL
            time.sleep(INTERVAL)

            # then retrieve the same info again
            for p in procs[:]:
                with p.oneshot():
                    try:
                        p._after = p.io_counters()
                        p._cmdline = ' '.join(p.cmdline())
                        if not p._cmdline:
                            p._cmdline = p.name()
                        p._username = p.username()
                    except (psutil.NoSuchProcess, psutil.ZombieProcess):
                        procs.remove(p)
            disks_after = psutil.disk_io_counters()

            # finally calculate results by comparing data before and
            # after the interval
            for p in procs:
                p._read_per_sec = p._after.read_bytes - p._before.read_bytes
                p._write_per_sec = p._after.write_bytes - p._before.write_bytes
                p._total = p._read_per_sec + p._write_per_sec

            diskIO["read"] = disks_after.read_bytes - disks_before.read_bytes
            diskIO["write"] = disks_after.write_bytes - disks_before.write_bytes


def update_ping_target(mark, new_host, new_port, new_name):
    """动态更新ping目标配置"""
    if mark and new_host and new_port and new_name:
        with ping_config_lock:
            ping_configs[mark] = {'host': new_host, 'port': new_port, 'name': new_name}
            logger.info(f"Updated {mark}: {new_host}:{new_port} {new_name}")


# 开始多线程
def get_realtime_data(string_json):
    """
    real time get system data
    :return:
    """

    # 创建动态ping线程
    ping_threads = []
    for mark in ping_configs:
        t = threading.Thread(
            target=_ping_thread,
            kwargs={'mark': mark},
            daemon=True
        )
        ping_threads.append(t)

    t4 = threading.Thread(target=_net_speed, daemon=True)
    t5 = threading.Thread(target=_disk_io, daemon=True)

    for ti in ping_threads + [t4, t5]:
        ti.start()


def byte_str(object):
    '''
    bytes to str, str to bytes
    :param object:
    :return:
    '''
    if isinstance(object, str):
        return object.encode(encoding="utf-8")
    elif isinstance(object, bytes):
        return bytes.decode(object)
    else:
        print(type(object))


def format_size(size):
    for unit in ['B', 'K', 'M', 'G', 'T', 'P']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0


def __check_docker_installed():
    try:
        subprocess.run(["docker", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False


def __get_docker_stats():
    client = docker.from_env()
    containers = client.containers.list(all=True)

    with ThreadPoolExecutor() as executor:
        container_stats = list(executor.map(__process_container_stats, containers))

    return container_stats


def __process_container_stats(container):
    if container.status in ['paused', 'exited']:
        return {
            'name': container.name,
            'id': container.id,
            'status': container.status,
            'cpu_usage': None,
            'memory_usage': None,
            'memory_limit': None,
            'network': None
        }

    stats = container.stats(stream=False)

    memory_usage = stats['memory_stats'].get('usage', None)
    memory_limit = stats['memory_stats'].get('limit', None)

    container_info = {
        'name': container.name,
        'id': container.id,
        'status': container.status,
        'cpu_usage': __calculate_cpu_percentage(stats),
        'memory_usage': memory_usage,
        'memory_limit': memory_limit,
        'network': __get_network_usage(container.id, stats)
    }
    return container_info


def __calculate_cpu_percentage(stats):
    if 'system_cpu_usage' not in stats['cpu_stats']:
        return 0.0

    cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - stats['precpu_stats']['cpu_usage']['total_usage']
    system_delta = stats['cpu_stats']['system_cpu_usage'] - stats['precpu_stats']['system_cpu_usage']
    online_cpus = stats['cpu_stats'].get('online_cpus', 1)

    if system_delta > 0 and cpu_delta > 0:
        return (cpu_delta / system_delta) * online_cpus * 100.0
    return 0.0


# 计算网络速度
def __get_network_usage(container_id, stats):
    global previous_network_stats
    current_time = time.time()

    # 提取当前的网络统计数据
    networks = stats.get('networks', {})
    speeds = {}

    if container_id not in previous_network_stats:
        previous_network_stats[container_id] = {}

    for net_name, net_stats in networks.items():
        prev_stats = previous_network_stats[container_id].get(net_name, {})
        rx_bytes = net_stats.get('rx_bytes', 0)
        tx_bytes = net_stats.get('tx_bytes', 0)
        prev_rx_bytes = prev_stats.get('rx_bytes', 0)
        prev_tx_bytes = prev_stats.get('tx_bytes', 0)
        prev_time = prev_stats.get('time', current_time)

        # 计算时间间隔
        time_diff = current_time - prev_time
        if time_diff > 0:
            rx_speed = (rx_bytes - prev_rx_bytes) / time_diff  # 接收速度 bytes/s
            tx_speed = (tx_bytes - prev_tx_bytes) / time_diff  # 发送速度 bytes/s
        else:
            rx_speed = tx_speed = 0

        speeds[net_name] = {
            'rx_speed': rx_speed,
            'tx_speed': tx_speed
        }

        # 更新上一次的网络数据
        previous_network_stats[container_id][net_name] = {
            'rx_bytes': rx_bytes,
            'tx_bytes': tx_bytes,
            'time': current_time
        }

    return speeds


def __get_stats():
    stats = __get_docker_stats()
    docker_dict.clear()
    for stat in stats:
        docker_data = {}
        if stat.get('status') in ['paused', 'exited']:
            docker_data["name"] = stat.get('name')
            docker_data["status"] = stat.get('status')
            docker_data["cpu_usage"] = "null"
            docker_data["memory_usage"] = "null"
            docker_data["rx_speed"] = "null"
            docker_data["tx_speed"] = "null"
            docker_dict[docker_data["name"]] = docker_data
            continue
        docker_data["name"] = stat.get('name')
        docker_data["status"] = stat.get('status')
        docker_data["cpu_usage"] = f"{stat.get('cpu_usage'):.2f}%"
        docker_data["memory_usage"] = format_size(stat.get('memory_usage'))
        for net_name, net_stat in stat.get('network').items():
            docker_data["rx_speed"] = format_size(net_stat.get('rx_speed'))
            docker_data["tx_speed"] = format_size(net_stat.get('tx_speed'))
        docker_dict[docker_data["name"]] = docker_data


def get_docker():
    while True:
        if __check_docker_installed():  # 首先检查是否安装了 Docker
            try:
                while True:
                    try:
                        __get_stats()
                    except:
                        logger.info("get_docker failed")
                    time.sleep(2)  # 每隔1秒钟更新一次
            except KeyboardInterrupt:
                logger.info("监控停止")
        time.sleep(30)  # 每隔1秒钟更新一次


def monitor_vps(uuid, priority, country_code, emoji, ipv4, ipv6, server, port, client_id):
    global threading_start
    socket.setdefaulttimeout(30)
    while 1:
        try:
            while True:
                logger.info("Connecting...")
                s = socket.create_connection((server, port))

                data = byte_str(s.recv(1024))
                logger.info(data)
                if data.find("Authentication required") > -1:
                    json_string = '{"Authentication":"' + client_id + '"}'
                    s.send(byte_str(json_string))
                    data = byte_str(s.recv(1024))
                    if data.find("Authentication successful") < 0:
                        logger.info(data)
                        s.close()
                        time.sleep(30)
                        raise socket.error

                s.send(byte_str("get arg"))
                data = byte_str(s.recv(1024))
                logger.info(data)
                if data.find("arg") > -1:
                    s.send(byte_str("arg succ"))

                    string_json = json.loads(data)
                    logger.info(string_json["arg"])
                    update_ping_target("10010", string_json["cu_ip"], string_json["cu_port"], string_json["cu_name"])
                    update_ping_target("189", string_json["ct_ip"], string_json["ct_port"], string_json["ct_name"])
                    update_ping_target("10086", string_json["cm_ip"], string_json["cm_port"], string_json["cm_name"])

                    if not threading_start:
                        # 创建并启动新线程
                        docker_thread = threading.Thread(target=get_docker)
                        docker_thread.start()
                        logger.info("启动监控线程")
                        get_realtime_data(string_json)
                    threading_start = True
                    logger.info("succ")
                    break
                time.sleep(3)

            while True:
                uptime = get_uptime()
                system_version = get_system_version()
                cpu_usage = get_cpu_usage()
                cpu_model = get_cpu_model()
                disk_total, disk_used = get_disk()
                memory_total, memory_used = get_memory()
                swap_total, swap_used = get_swap()
                network_in, network_out = get_network()
                load_avg = get_load_average()

                array = {}
                array["version"] = "2.0.0"
                array["uuid"] = uuid
                array["client_id"] = client_id
                array["priority"] = priority
                array["country_code"] = country_code
                array["emoji"] = emoji
                array["ipv4"] = ipv4
                array["ipv6"] = ipv6
                # 服务器运行时间
                array["server_uptime"] = uptime
                # 系统版本
                array["system_version"] = system_version
                # CPU版本
                array["cpu_model"] = cpu_model
                array["cpu_usage"] = cpu_usage
                # 硬盘总大小
                array["disk_total_size"] = format_size(disk_total)
                # 硬盘已使用大小:
                array["disk_used_size"] = format_size(disk_used)
                # 内存总大小
                array["memory_total_size"] = format_size(memory_total)
                # 内存已使用大小
                array["memory_used_size"] = format_size(memory_used)
                # 交换总大小
                array["swap_total_size"] = format_size(swap_total)
                # 交换已使用大小
                array["swap_used_size"] = format_size(swap_used)
                # 流量上传大小
                array["network_upload_size"] = format_size(network_out)
                # 流量下载大小
                array["network_download_size"] = format_size(network_in)
                # 上传速度
                array['network_rx'] = format_size(netSpeed.get("netrx"))
                # 下载速度
                array['network_tx'] = format_size(netSpeed.get("nettx"))
                # 3个负载
                array["load_averages"] = f"{load_avg[0]:.2f},{load_avg[1]:.2f},{load_avg[2]:.2f}"
                # TCP数、UDP数、进程数、线程数
                array['tcp'], array['udp'], array['process'], array['thread'] = tupd()
                # 磁盘读取速度
                array['io_read'] = format_size(diskIO.get("read"))
                # 磁盘写入速度
                array['io_write'] = format_size(diskIO.get("write"))
                # docker容器的名字
                array['dockers'] = docker_dict

                with ping_config_lock:
                    config = ping_configs.get("10010", {})
                    array['name_10010'] = config.get("name", {})
                    config = ping_configs.get("189", {})
                    array['name_189'] = config.get("name", {})
                    config = ping_configs.get("10086", {})
                    array['name_10086'] = config.get("name", {})
                array['ping_10010'] = lostRate.get('10010') * 100
                array['ping_189'] = lostRate.get('189') * 100
                array['ping_10086'] = lostRate.get('10086') * 100
                array['time_10010'] = pingTime.get('10010')
                array['time_189'] = pingTime.get('189')
                array['time_10086'] = pingTime.get('10086')

                json_str = json.dumps(array)
                s.send(byte_str("update:" + json_str + "`"))
                # time.sleep(1)

                # 等待1秒并处理接收数据
                start_time = time.time()
                end_time = start_time + 1  # 下次发送的时间戳
                while time.time() < end_time:
                    remaining = end_time - time.time()
                    if remaining <= 0:
                        break
                    # 监视套接字可读事件
                    rlist, _, _ = select.select([s], [], [], remaining)
                    if s in rlist:
                        try:
                            data = byte_str(s.recv(1024))
                            if not data:
                                raise socket.error("Connection closed by server")
                            logger.info(f"Received data: {data}")
                            # 处理接收到的数据（示例：简单打印）
                            if data.find("arg") > -1:
                                string_json = json.loads(data)
                                if string_json["arg"] == "update_ping":
                                    update_ping_target("10010", string_json["cu_ip"], string_json["cu_port"], string_json["cu_name"])
                                    update_ping_target("189", string_json["ct_ip"], string_json["ct_port"], string_json["ct_name"])
                                    update_ping_target("10086", string_json["cm_ip"], string_json["cm_port"], string_json["cm_name"])

                        except socket.error as e:
                            logger.error(f"Socket error: {e}")
                            raise  # 触发外层重新连接

        except KeyboardInterrupt:
            raise
        except socket.error:
            logger.info("Disconnected...")
            if 's' in locals().keys():
                del s
            time.sleep(3)
        except Exception as e:
            logger.info("Caught Exception:", e)
            if 's' in locals().keys():
                del s
            time.sleep(3)


if __name__ == '__main__':
    ipv4 = ''
    ipv6 = ''
    url = ''
    uuid = ''
    client_id = ''
    for argc in sys.argv:
        if 'URL' in argc:
            url = argc.split('URL=')[-1]
        elif 'UUID' in argc:
            uuid = argc.split('UUID=')[-1]
        elif 'Client_ID' in argc:
            client_id = argc.split('Client_ID=')[-1]

    priority, country_code, emoji, ipv4, ipv6 = get_client_ip()
    server, port = get_server_ip(url, ipv4, ipv6)
    if not server or not port:
        raise "SERVER or PORT is null"
    logger.info(f" IP {ipv4, ipv6} SERVER {server} PORT {port} UUID {uuid}")

    # 启动数据收集的线程，每隔一秒运行一次
    thread = threading.Thread(target=monitor_vps, args=(uuid, priority, country_code, emoji, ipv4, ipv6, server, port, client_id,))
    thread.start()
    while True:
        time.sleep(21600)
        priority1, country_code1, emoji1, ipv41, ipv61 = get_client_ip()
        if ipv41 or ipv61 or priority1 or country_code1 or emoji1:
            priority, country_code, emoji, ipv4, ipv6 = priority, country_code, emoji, ipv4, ipv6
            logger.info(f'ip_addr get success')
        else:
            logger.info(f'ip_addr get failed')

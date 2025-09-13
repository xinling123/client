package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	VERSION                  = "2.0.0"
	PROBE_PROTOCOL_PREFER    = "ipv4"
	PING_PACKET_HISTORY_LEN  = 100
	INTERVAL                 = 1
	LOG_FILE_PATH           = "/root/server_watch.log"
	MAX_LOG_SIZE            = 20 * 1024 * 1024 // 20 MB
	BACKUP_COUNT            = 5
)

// 配置结构
type PingConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	Name string `json:"name"`
}

type ClientConfig struct {
	URL      string
	UUID     string
	ClientID string
}

// 全局变量
var (
	pingConfigs = map[string]*PingConfig{
		"10010": {Host: "cu.tz.cloudcpp.com", Port: 80, Name: ""},
		"189":   {Host: "ct.tz.cloudcpp.com", Port: 80, Name: ""},
		"10086": {Host: "cm.tz.cloudcpp.com", Port: 80, Name: ""},
	}
	pingConfigLock = sync.RWMutex{}
	
	lostRate = map[string]float64{
		"10010": 0.0,
		"189":   0.0,
		"10086": 0.0,
	}
	lostRateLock = sync.RWMutex{}
	
	pingTime = map[string]int64{
		"10010": 0,
		"189":   0,
		"10086": 0,
	}
	pingTimeLock = sync.RWMutex{}
	
	netSpeed = struct {
		NetRx  int64
		NetTx  int64
		Clock  float64
		Diff   float64
		AvgRx  int64
		AvgTx  int64
		mu     sync.RWMutex
	}{}
	
	diskIO = struct {
		Read  uint64
		Write uint64
		mu    sync.RWMutex
	}{}
	
	dockerStats = make(map[string]map[string]interface{})
	dockerMutex = sync.RWMutex{}
	
	// Docker网络统计历史数据
	dockerNetworkHistory = make(map[string]map[string]interface{})
	dockerNetworkMutex   = sync.RWMutex{}
	
	logger *log.Logger
	
	// 全局监控线程管理
	monitoringStarted = false
	monitoringMutex   = sync.Mutex{}
	
	// 全局context用于优雅关闭
	globalCtx, globalCancel = context.WithCancel(context.Background())
	
	// 用于等待所有goroutine结束
	globalWaitGroup = sync.WaitGroup{}
)

// 清理旧的Docker网络历史数据，防止内存泄漏
func cleanupOldNetworkHistory() {
	dockerNetworkMutex.Lock()
	defer dockerNetworkMutex.Unlock()
	
	now := time.Now().Unix()
	for containerName, history := range dockerNetworkHistory {
		if lastTime, ok := history["time"].(int64); ok {
			// 清理超过10分钟的旧数据
			if now-lastTime > 600 {
				delete(dockerNetworkHistory, containerName)
				logger.Printf("Cleaned up old network history for container: %s", containerName)
			}
		}
	}
}

// 监控goroutine数量和内存使用情况
func monitorGoroutines(ctx context.Context) {
	defer globalWaitGroup.Done()
	
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			logger.Println("Goroutine monitor stopping...")
			return
		case <-ticker.C:
			numGoroutines := runtime.NumGoroutine()
			if numGoroutines > 1000 {
				logger.Printf("WARNING: High goroutine count: %d", numGoroutines)
			}
			
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			
			// 记录内存使用情况
			allocMB := m.Alloc / 1024 / 1024
			sysMB := m.Sys / 1024 / 1024
			
			if allocMB > 500 { // 如果分配的内存超过500MB，记录警告
				logger.Printf("WARNING: High memory usage - Alloc=%d MB, Sys=%d MB, NumGC=%d, Goroutines=%d", 
					allocMB, sysMB, m.NumGC, numGoroutines)
			}
			
			// 如果内存使用过高，强制进行垃圾回收
			if allocMB > 1000 {
				logger.Println("Force garbage collection due to high memory usage")
				runtime.GC()
			}
		}
	}
}

// 初始化日志系统
func initLogger() {
	logPath := LOG_FILE_PATH
	if runtime.GOOS == "windows" {
		logPath = "server_watch.log"
	}
	
	lumberjackLogger := &lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    MAX_LOG_SIZE / (1024 * 1024), // MB
		MaxBackups: BACKUP_COUNT,
		MaxAge:     30, // days
		Compress:   true,
	}
	
	logger = log.New(lumberjackLogger, "", log.LstdFlags)
}


// 获取客户端IP信息
func getClientIP() (priority, countryCode, emoji, ipv4, ipv6 string) {
	client := &http.Client{Timeout: 10 * time.Second}
	
	// 获取优先IP
	resp, err := client.Post("https://test.ipw.cn", "application/json", nil)
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		n, _ := resp.Body.Read(buf)
		priority = strings.TrimSpace(string(buf[:n]))
	}
	
	// 获取国家信息
	if priority != "" {
		resp, err := client.Get(fmt.Sprintf("http://ipwho.is/%s", priority))
		if err == nil {
			defer resp.Body.Close()
			var result map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&result)
			if cc, ok := result["country_code"].(string); ok {
				countryCode = cc
			}
			if flagObj, ok := result["flag"].(map[string]interface{}); ok {
				// 将整个flag对象转换为JSON字符串保存
				if flagJSON, err := json.Marshal(flagObj); err == nil {
					emoji = string(flagJSON)
				}
			}
		}
	}
	
	// 获取IPv4
	resp, err = client.Get("https://4.ipw.cn/")
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		n, _ := resp.Body.Read(buf)
		ipv4 = strings.TrimSpace(string(buf[:n]))
	}
	
	// 获取IPv6
	resp, err = client.Get("https://6.ipw.cn/")
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		n, _ := resp.Body.Read(buf)
		ipv6 = strings.TrimSpace(string(buf[:n]))
	}
	
	logger.Printf("IP Info: priority=%s, country=%s, emoji=%s, ipv4=%s, ipv6=%s", 
		priority, countryCode, emoji, ipv4, ipv6)
	
	return
}

// 获取服务器IP和端口
func getServerIP(url, ipv4, ipv6 string) (server string, port int) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		logger.Printf("Failed to get server info: %v", err)
		return
	}
	defer resp.Body.Close()
	
	var result []interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Printf("Failed to decode server info: %v", err)
		return
	}
	
	if len(result) >= 3 {
		if ipv4 != "" {
			server = result[0].(string)
		} else if ipv6 != "" {
			server = result[1].(string)
		}
		port = int(result[2].(float64))
	}
	
	return
}

// 获取CPU使用率
func getCPUUsage() []float64 {
	percentages, err := cpu.Percent(time.Second, true)
	if err != nil {
		logger.Printf("Failed to get CPU usage: %v", err)
		return []float64{0}
	}
	return percentages
}

// 获取CPU型号
func getCPUModel() string {
	info, err := cpu.Info()
	if err != nil || len(info) == 0 {
		return "Unknown"
	}
	return info[0].ModelName
}

// 获取系统版本
func getSystemVersion() string {
	info, err := host.Info()
	if err != nil {
		return runtime.GOOS + " " + runtime.GOARCH
	}
	return fmt.Sprintf("%s %s %s", info.OS, info.Platform, info.PlatformVersion)
}

// 获取系统启动时间
func getUptime() string {
	info, err := host.Info()
	if err != nil {
		return "Unknown"
	}
	bootTime := time.Unix(int64(info.BootTime), 0)
	return bootTime.Format("2006/01/02 15:04:05")
}

// 获取内存信息
func getMemory() (total, used uint64) {
	v, err := mem.VirtualMemory()
	if err != nil {
		return 0, 0
	}
	return v.Total, v.Used
}

// 获取交换内存信息
func getSwap() (total, used uint64) {
	s, err := mem.SwapMemory()
	if err != nil {
		return 0, 0
	}
	return s.Total, s.Used
}

// 获取磁盘信息
func getDisk() (total, used uint64) {
	// 处理macOS和Windows的简单情况
	if runtime.GOOS == "darwin" {
		usage, err := disk.Usage("/")
		if err != nil {
			return 0, 0
		}
		return usage.Total, usage.Used
	}
	
	if runtime.GOOS == "windows" {
		// Windows: 获取所有驱动器
		partitions, err := disk.Partitions(false)
		if err != nil {
			return 0, 0
		}
		
		for _, partition := range partitions {
			// Windows驱动器通常是 C:\, D:\ 等
			if len(partition.Mountpoint) >= 2 && partition.Mountpoint[1] == ':' {
				usage, err := disk.Usage(partition.Mountpoint)
				if err != nil {
					continue
				}
				total += usage.Total
				used += usage.Used
			}
		}
		return
	}
	
	// Linux和其他Unix系统
	var validFS = map[string]bool{
		"ext4": true, "ext3": true, "ext2": true, "reiserfs": true,
		"jfs": true, "btrfs": true, "fuseblk": true, "zfs": true,
		"simfs": true, "ntfs": true, "fat32": true, "exfat": true, 
		"xfs": true, "vfat": true,
	}
	
	// 排除的挂载点和设备类型
	excludeMountpoints := map[string]bool{
		"/dev":     true,
		"/proc":    true,
		"/sys":     true,
		"/run":     true,
		"/boot":    false, // boot分区应该被计算
		"/tmp":     false, // 如果tmp是独立分区应该被计算
		"/var/log": false, // 如果是独立分区应该被计算
	}
	
	partitions, err := disk.Partitions(false)
	if err != nil {
		return 0, 0
	}
	
	// 使用挂载点而不是设备名来避免重复计算
	processedMountpoints := make(map[string]bool)
	
	for _, partition := range partitions {
		// 跳过无效的文件系统类型
		if !validFS[strings.ToLower(partition.Fstype)] {
			continue
		}
		
		// 跳过已处理的挂载点
		if processedMountpoints[partition.Mountpoint] {
			continue
		}
		
		// 跳过特定的系统挂载点
		if exclude, exists := excludeMountpoints[partition.Mountpoint]; exists && exclude {
			continue
		}
		
		// 跳过明显的虚拟文件系统
		if strings.HasPrefix(partition.Device, "/dev/loop") ||
			strings.HasPrefix(partition.Device, "tmpfs") ||
			strings.HasPrefix(partition.Device, "devtmpfs") ||
			strings.HasPrefix(partition.Device, "udev") ||
			strings.HasPrefix(partition.Device, "overlay") ||
			strings.HasPrefix(partition.Device, "shm") {
			continue
		}
		
		// 获取磁盘使用情况
		usage, err := disk.Usage(partition.Mountpoint)
		if err != nil {
			logger.Printf("Failed to get disk usage for %s: %v", partition.Mountpoint, err)
			continue
		}
		
		// 跳过大小为0的文件系统
		if usage.Total == 0 {
			continue
		}
		
		processedMountpoints[partition.Mountpoint] = true
		total += usage.Total
		used += usage.Used
	}
	
	return
}

// 获取网络总流量
func getNetwork() (networkIn, networkOut uint64) {
	stats, err := psnet.IOCounters(true)
	if err != nil {
		return 0, 0
	}
	
	for _, stat := range stats {
		name := stat.Name
		if strings.Contains(name, "lo") || strings.Contains(name, "tun") ||
			strings.Contains(name, "docker") || strings.Contains(name, "veth") ||
			strings.Contains(name, "br-") || strings.Contains(name, "vmbr") ||
			strings.Contains(name, "vnet") || strings.Contains(name, "kube") {
			continue
		}
		networkIn += stat.BytesRecv
		networkOut += stat.BytesSent
	}
	
	return
}

// 获取TCP、UDP、进程数、线程数
func getTUPD() (tcp, udp, processes, threads int) {
	// 获取进程数
	pids, err := process.Pids()
	if err == nil {
		processes = len(pids)
		
		// 计算线程数
		for _, pid := range pids {
			if p, err := process.NewProcess(pid); err == nil {
				if numThreads, err := p.NumThreads(); err == nil {
					threads += int(numThreads)
				}
			}
		}
	}
	
	// 获取网络连接数
	connections, err := psnet.Connections("all")
	if err == nil {
		for _, conn := range connections {
			switch conn.Type {
			case 1: // SOCK_STREAM (TCP)
				tcp++
			case 2: // SOCK_DGRAM (UDP)
				udp++
			}
		}
	}
	
	return
}

// 获取负载平均值
func getLoadAverage() [3]float64 {
	avg, err := load.Avg()
	if err != nil {
		return [3]float64{0, 0, 0}
	}
	return [3]float64{avg.Load1, avg.Load5, avg.Load15}
}

// Ping线程
func pingThread(ctx context.Context, mark string) {
	defer globalWaitGroup.Done()
	
	lostPacket := 0
	packetHistory := make([]int, 0, PING_PACKET_HISTORY_LEN)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			logger.Printf("Ping thread for %s stopping...", mark)
			return
		case <-ticker.C:
			pingConfigLock.RLock()
			config := pingConfigs[mark]
			host := config.Host
			port := config.Port
			pingConfigLock.RUnlock()
			
			// 解析IP地址
			ip := host
			if !strings.Contains(host, ":") { // 不是IPv6地址
				addrs, err := net.LookupHost(host)
				if err == nil && len(addrs) > 0 {
					ip = addrs[0]
				}
			}
			
			// 测试连接
			start := time.Now()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), time.Second)
			duration := time.Since(start)
			
			if len(packetHistory) >= PING_PACKET_HISTORY_LEN {
				if packetHistory[0] == 0 {
					lostPacket--
				}
				packetHistory = packetHistory[1:]
			}
			
			if err == nil {
				conn.Close()
				pingTimeLock.Lock()
				pingTime[mark] = duration.Milliseconds()
				pingTimeLock.Unlock()
				packetHistory = append(packetHistory, 1)
			} else {
				lostPacket++
				packetHistory = append(packetHistory, 0)
			}
			
			if len(packetHistory) > 30 {
				lostRateLock.Lock()
				lostRate[mark] = float64(lostPacket) / float64(len(packetHistory))
				lostRateLock.Unlock()
			}
		}
	}
}

// 网络速度监控
func netSpeedMonitor(ctx context.Context) {
	defer globalWaitGroup.Done()
	
	ticker := time.NewTicker(time.Duration(INTERVAL) * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			logger.Println("Network speed monitor stopping...")
			return
		case <-ticker.C:
			stats, err := psnet.IOCounters(true)
			if err != nil {
				continue
			}
			
			var avgRx, avgTx uint64
			for _, stat := range stats {
				name := stat.Name
				if strings.Contains(name, "lo") || strings.Contains(name, "tun") ||
					strings.Contains(name, "docker") || strings.Contains(name, "veth") ||
					strings.Contains(name, "br-") || strings.Contains(name, "vmbr") ||
					strings.Contains(name, "vnet") || strings.Contains(name, "kube") {
					continue
				}
				avgRx += stat.BytesRecv
				avgTx += stat.BytesSent
			}
			
			nowClock := float64(time.Now().Unix())
			
			netSpeed.mu.Lock()
			netSpeed.Diff = nowClock - netSpeed.Clock
			netSpeed.Clock = nowClock
			if netSpeed.Diff > 0 {
				netSpeed.NetRx = int64((float64(avgRx) - float64(netSpeed.AvgRx)) / netSpeed.Diff)
				netSpeed.NetTx = int64((float64(avgTx) - float64(netSpeed.AvgTx)) / netSpeed.Diff)
			}
			netSpeed.AvgRx = int64(avgRx)
			netSpeed.AvgTx = int64(avgTx)
			netSpeed.mu.Unlock()
		}
	}
}

// 磁盘IO监控
func diskIOMonitor(ctx context.Context) {
	defer globalWaitGroup.Done()
	
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		// macOS和Windows暂不处理磁盘IO
		logger.Println("Disk IO monitoring not supported on this platform")
		return
	}
	
	ticker := time.NewTicker(time.Duration(INTERVAL) * time.Second)
	defer ticker.Stop()
	
	var before map[string]disk.IOCountersStat
	
	for {
		select {
		case <-ctx.Done():
			logger.Println("Disk IO monitor stopping...")
			return
		case <-ticker.C:
			after, err := disk.IOCounters()
			if err != nil {
				continue
			}
			
			if before != nil {
				var totalRead, totalWrite uint64
				for device := range before {
					if afterStat, ok := after[device]; ok {
						if beforeStat, ok := before[device]; ok {
							totalRead += afterStat.ReadBytes - beforeStat.ReadBytes
							totalWrite += afterStat.WriteBytes - beforeStat.WriteBytes
						}
					}
				}
				
				diskIO.mu.Lock()
				diskIO.Read = totalRead
				diskIO.Write = totalWrite
				diskIO.mu.Unlock()
			}
			
			before = after
		}
	}
}

// 检查Docker是否安装
func checkDockerInstalled() bool {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return false
	}
	defer cli.Close()
	
	_, err = cli.Ping(context.Background())
	return err == nil
}

// Docker监控 - 持续收集容器数据，每个容器完成后立即更新到缓冲区
func dockerMonitor(ctx context.Context) {
	defer globalWaitGroup.Done()
	
	// 创建一个用于清理历史数据的ticker
	cleanupTicker := time.NewTicker(5 * time.Minute)
	defer cleanupTicker.Stop()
	
	// 容器监控ticker
	containerTicker := time.NewTicker(3 * time.Second)
	defer containerTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Println("Docker monitor stopping...")
			return
		case <-cleanupTicker.C:
			// 定期清理旧的网络历史数据
			cleanupOldNetworkHistory()
		case <-containerTicker.C:
			if !checkDockerInstalled() {
				continue
			}

			cli, err := client.NewClientWithOpts(client.FromEnv)
			if err != nil {
				continue
			}

			containers, err := cli.ContainerList(ctx, types.ContainerListOptions{All: true})
			if err != nil {
				cli.Close()
				continue
			}

			// 使用信号量限制并发goroutine数量
			semaphore := make(chan struct{}, 10) // 最多同时处理10个容器
			var containerWg sync.WaitGroup

			// 为每个容器启动独立的goroutine，完成后立即更新缓冲区
			for _, container := range containers {
				containerWg.Add(1)
				go func(container types.Container) {
					defer containerWg.Done()
					
					// 获取信号量
					select {
					case semaphore <- struct{}{}:
						defer func() { <-semaphore }() // 释放信号量
					case <-ctx.Done():
						return // 如果context已取消，直接返回
					}

					containerName := strings.TrimPrefix(container.Names[0], "/")
					containerData := collectSingleContainerData(cli, container, containerName)

					// 立即更新到全局缓冲区，替换该容器的旧数据
					dockerMutex.Lock()
					if dockerStats == nil {
						dockerStats = make(map[string]map[string]interface{})
					}
					dockerStats[containerName] = containerData
					dockerMutex.Unlock()
				}(container)
			}

			// 等待所有容器goroutine完成，但也要监听context取消
			done := make(chan struct{})
			go func() {
				containerWg.Wait()
				close(done)
			}()

			select {
			case <-done:
				// 所有容器处理完成
			case <-ctx.Done():
				// context已取消，不等待容器处理完成
				cli.Close()
				return
			}

			cli.Close()
		}
	}
}

// 收集单个容器的数据
func collectSingleContainerData(cli *client.Client, container types.Container, containerName string) map[string]interface{} {
	containerData := make(map[string]interface{})
	containerData["name"] = containerName
	containerData["status"] = container.State

	if container.State == "running" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		stats, err := cli.ContainerStats(ctx, container.ID, false)
		if err == nil && stats.Body != nil {
			defer stats.Body.Close()
			
			var statsData types.StatsJSON
			decoder := json.NewDecoder(stats.Body)
			if err := decoder.Decode(&statsData); err == nil {
				// CPU使用率计算
				cpuDelta := float64(statsData.CPUStats.CPUUsage.TotalUsage - statsData.PreCPUStats.CPUUsage.TotalUsage)
				systemDelta := float64(statsData.CPUStats.SystemUsage - statsData.PreCPUStats.SystemUsage)
				onlineCPUs := float64(statsData.CPUStats.OnlineCPUs)
				if onlineCPUs == 0 {
					onlineCPUs = 1
				}

				var cpuPercent float64
				if systemDelta > 0 && cpuDelta > 0 {
					cpuPercent = (cpuDelta / systemDelta) * onlineCPUs * 100.0
				}

				containerData["cpu_usage"] = fmt.Sprintf("%.2f%%", cpuPercent)
				containerData["memory_usage"] = statsData.MemoryStats.Usage

				// 计算网络速度
				var currentRxBytes, currentTxBytes uint64
				for _, network := range statsData.Networks {
					currentRxBytes += network.RxBytes
					currentTxBytes += network.TxBytes
				}

				currentTime := time.Now().Unix()

				// 获取历史数据来计算速度
				dockerNetworkMutex.Lock()
				if history, exists := dockerNetworkHistory[containerName]; exists {
					if lastTime, ok := history["time"].(int64); ok {
						if lastRx, ok := history["rx_bytes"].(uint64); ok {
							if lastTx, ok := history["tx_bytes"].(uint64); ok {
								timeDiff := currentTime - lastTime
								if timeDiff > 0 {
									rxSpeed := (currentRxBytes - lastRx) / uint64(timeDiff)
									txSpeed := (currentTxBytes - lastTx) / uint64(timeDiff)
									containerData["rx_speed"] = rxSpeed
									containerData["tx_speed"] = txSpeed
								} else {
									containerData["rx_speed"] = uint64(0)
									containerData["tx_speed"] = uint64(0)
								}
							}
						}
					}
				} else {
					containerData["rx_speed"] = uint64(0)
					containerData["tx_speed"] = uint64(0)
				}

				// 更新历史数据
				dockerNetworkHistory[containerName] = map[string]interface{}{
					"time":     currentTime,
					"rx_bytes": currentRxBytes,
					"tx_bytes": currentTxBytes,
				}
				dockerNetworkMutex.Unlock()
			} else {
				// 解析失败
				containerData["cpu_usage"] = "null"
				containerData["memory_usage"] = "null"
				containerData["rx_speed"] = "null"
				containerData["tx_speed"] = "null"
			}
		} else {
			// stats 请求失败
			containerData["cpu_usage"] = "null"
			containerData["memory_usage"] = "null"
			containerData["rx_speed"] = "null"
			containerData["tx_speed"] = "null"
		}
	} else {
		// 非运行状态
		containerData["cpu_usage"] = "null"
		containerData["memory_usage"] = "null"
		containerData["rx_speed"] = "null"
		containerData["tx_speed"] = "null"
	}

	return containerData
}

// 更新ping目标
func updatePingTarget(mark, newHost string, newPort int, newName string) {
	if mark != "" && newHost != "" && newPort > 0 {
		pingConfigLock.Lock()
		pingConfigs[mark] = &PingConfig{
			Host: newHost,
			Port: newPort,
			Name: newName,
		}
		pingConfigLock.Unlock()
		logger.Printf("Updated %s: %s:%d %s", mark, newHost, newPort, newName)
	}
}

// 启动实时数据收集
func startRealtimeDataCollection(ctx context.Context) {
	monitoringMutex.Lock()
	defer monitoringMutex.Unlock()
	
	if monitoringStarted {
		logger.Println("Monitoring threads already started, skipping...")
		return // 已经启动，避免重复启动
	}
	
	logger.Println("Starting monitoring threads...")
	
	// 启动ping线程
	for mark := range pingConfigs {
		globalWaitGroup.Add(1)
		go pingThread(ctx, mark)
	}
	
	// 启动网络速度监控
	globalWaitGroup.Add(1)
	go netSpeedMonitor(ctx)
	
	// 启动磁盘IO监控
	globalWaitGroup.Add(1)
	go diskIOMonitor(ctx)
	
	// 启动Docker监控
	globalWaitGroup.Add(1)
	go dockerMonitor(ctx)
	
	// 启动资源监控
	globalWaitGroup.Add(1)
	go monitorGoroutines(ctx)
	
	monitoringStarted = true
	logger.Println("All monitoring threads started successfully")
}

// 主监控函数
func monitorVPS(config ClientConfig, priority, countryCode, emoji, ipv4, ipv6, server string, port int) {
	threadingStart := false
	
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Printf("Panic recovered: %v", r)
				}
			}()
			
			// 连接服务器
			logger.Printf("Connecting to %s:%d...", server, port)
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", server, port), 10*time.Second)
			if err != nil {
				logger.Printf("Failed to connect to %s:%d - %v", server, port, err)
				time.Sleep(3 * time.Second)
				return
			}
			defer conn.Close()
			logger.Printf("Connected successfully to %s:%d", server, port)
			
			// 设置读取超时
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			
			// 认证过程 - 直接读取原始数据，不依赖换行符
			logger.Println("Reading initial server response...")
			buffer := make([]byte, 1024)
			n, err := conn.Read(buffer)
			if err != nil {
				logger.Printf("Failed to read server response: %v", err)
				return
			}
			
			// 清除读取超时
			conn.SetReadDeadline(time.Time{})
			
			data := string(buffer[:n])
			logger.Printf("Received: %s", strings.TrimSpace(data))
			
			if strings.Contains(data, "Authentication required") {
				authData := map[string]string{
					"Authentication": config.ClientID,
					"vps_ip":        ipv4 + "," + ipv6,
				}
				authJSON, _ := json.Marshal(authData)
				
				logger.Printf("Sending authentication: %s", string(authJSON))
				_, err = conn.Write(authJSON)
				if err != nil {
					logger.Printf("Failed to write auth: %v", err)
					return
				}
				
				logger.Println("Waiting for authentication response...")
				conn.SetReadDeadline(time.Now().Add(10 * time.Second))
				n, err = conn.Read(buffer)
				conn.SetReadDeadline(time.Time{})
				if err != nil {
					logger.Printf("Failed to read auth response: %v", err)
					return
				}
				
				authResponse := string(buffer[:n])
				logger.Printf("Auth response: %s", strings.TrimSpace(authResponse))
				
				if !strings.Contains(authResponse, "Authentication successful") {
					logger.Printf("Authentication failed: %s", strings.TrimSpace(authResponse))
					time.Sleep(30 * time.Second)
					return
				}
			}
			
			// 获取参数
			logger.Println("Requesting server arguments...")
			_, err = conn.Write([]byte("get arg"))
			if err != nil {
				logger.Printf("Failed to write get arg: %v", err)
				return
			}
			
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, err = conn.Read(buffer)
			conn.SetReadDeadline(time.Time{})
			if err != nil {
				logger.Printf("Failed to read arg: %v", err)
				return
			}
			
			data = string(buffer[:n])
			
			logger.Printf("Received arg: %s", strings.TrimSpace(data))
			
			if strings.Contains(data, "arg") {
				_, err = conn.Write([]byte("arg succ"))
				if err != nil {
					logger.Printf("Failed to write arg succ: %v", err)
					return
				}
				
				var argData map[string]interface{}
				if err := json.Unmarshal([]byte(strings.TrimSpace(data)), &argData); err == nil {
					if arg, ok := argData["arg"].(map[string]interface{}); ok {
						if cuIP, ok := arg["cu_ip"].(string); ok {
							if cuPort, ok := arg["cu_port"].(float64); ok {
								if cuName, ok := arg["cu_name"].(string); ok {
									updatePingTarget("10010", cuIP, int(cuPort), cuName)
								}
							}
						}
						if ctIP, ok := arg["ct_ip"].(string); ok {
							if ctPort, ok := arg["ct_port"].(float64); ok {
								if ctName, ok := arg["ct_name"].(string); ok {
									updatePingTarget("189", ctIP, int(ctPort), ctName)
								}
							}
						}
						if cmIP, ok := arg["cm_ip"].(string); ok {
							if cmPort, ok := arg["cm_port"].(float64); ok {
								if cmName, ok := arg["cm_name"].(string); ok {
									updatePingTarget("10086", cmIP, int(cmPort), cmName)
								}
							}
						}
					}
				}
				
				if !threadingStart {
					logger.Println("Starting monitoring threads...")
					startRealtimeDataCollection(globalCtx)
					threadingStart = true
				}
			}
			
			// 主循环 - 发送系统数据
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			
			for {
				select {
				case <-ticker.C:
					// 收集系统数据
					uptime := getUptime()
					systemVersion := getSystemVersion()
					cpuUsage := getCPUUsage()
					cpuModel := getCPUModel()
					diskTotal, diskUsed := getDisk()
					memoryTotal, memoryUsed := getMemory()
					swapTotal, swapUsed := getSwap()
					networkIn, networkOut := getNetwork()
					loadAvg := getLoadAverage()
					tcp, udp, processes, threads := getTUPD()
					
					// 构建数据包
					data := map[string]interface{}{
						"version":       VERSION,
						"uuid":          config.UUID,
						"client_id":     config.ClientID,
						"priority":      priority,
						"country_code":  countryCode,
						"emoji":         emoji,
						"ipv4":          ipv4,
						"ipv6":          ipv6,
						"server_uptime": uptime,
						"system_version": systemVersion,
						"cpu_model":     cpuModel,
						"cpu_usage":     cpuUsage,
						"disk_total_size": diskTotal,
						"disk_used_size":  diskUsed,
						"memory_total_size": memoryTotal,
						"memory_used_size":  memoryUsed,
						"swap_total_size":   swapTotal,
						"swap_used_size":    swapUsed,
						"network_upload_size": networkOut,
						"network_download_size": networkIn,
						"load_averages": fmt.Sprintf("%.2f,%.2f,%.2f", loadAvg[0], loadAvg[1], loadAvg[2]),
						"tcp":     tcp,
						"udp":     udp,
						"process": processes,
						"thread":  threads,
					}
					
					// 添加网络速度
					netSpeed.mu.RLock()
					data["network_rx"] = uint64(netSpeed.NetRx)
					data["network_tx"] = uint64(netSpeed.NetTx)
					netSpeed.mu.RUnlock()
					
					// 添加磁盘IO
					diskIO.mu.RLock()
					data["io_read"] = diskIO.Read
					data["io_write"] = diskIO.Write
					diskIO.mu.RUnlock()
					
					// 添加ping数据
					pingConfigLock.RLock()
					data["name_10010"] = pingConfigs["10010"].Name
					data["name_189"] = pingConfigs["189"].Name
					data["name_10086"] = pingConfigs["10086"].Name
					pingConfigLock.RUnlock()
					
					lostRateLock.RLock()
					data["ping_10010"] = lostRate["10010"] * 100
					data["ping_189"] = lostRate["189"] * 100
					data["ping_10086"] = lostRate["10086"] * 100
					lostRateLock.RUnlock()
					
					pingTimeLock.RLock()
					data["time_10010"] = pingTime["10010"]
					data["time_189"] = pingTime["189"]
					data["time_10086"] = pingTime["10086"]
					pingTimeLock.RUnlock()
					
					// 添加Docker数据：先复制一份快照，避免并发读写并允许部分数据发送
					dockerMutex.RLock()
					dockerSnapshot := make(map[string]map[string]interface{}, len(dockerStats))
					for k, v := range dockerStats {
						// 对每个容器的数据做浅拷贝，避免被并发修改
						item := make(map[string]interface{}, len(v))
						for ik, iv := range v {
							item[ik] = iv
						}
						dockerSnapshot[k] = item
					}
					dockerMutex.RUnlock()
					data["dockers"] = dockerSnapshot
					
					// 发送数据
					jsonData, err := json.Marshal(data)
					if err != nil {
						logger.Printf("Failed to marshal data: %v", err)
						continue
					}
					
					message := fmt.Sprintf("update:%s`", string(jsonData))
					// logger.Printf("send data: %s", message)
					_, err = conn.Write([]byte(message))
					if err != nil {
						logger.Printf("Failed to send data: %v", err)
						return
					}
					
					// 检查是否有服务器响应（非阻塞）
					conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
					responseBuffer := make([]byte, 1024)
					n, err := conn.Read(responseBuffer)
					if err == nil && n > 0 {
						response := string(responseBuffer[:n])
						logger.Printf("Server response: %s", strings.TrimSpace(response))
						
						// 处理更新ping目标的命令
						if strings.Contains(response, "arg") {
							var responseData map[string]interface{}
							if err := json.Unmarshal([]byte(strings.TrimSpace(response)), &responseData); err == nil {
								if arg, ok := responseData["arg"].(string); ok && arg == "update_ping" {
									// 更新ping目标配置
									if cuIP, ok := responseData["cu_ip"].(string); ok {
										if cuPort, ok := responseData["cu_port"].(float64); ok {
											if cuName, ok := responseData["cu_name"].(string); ok {
												updatePingTarget("10010", cuIP, int(cuPort), cuName)
											}
										}
									}
								}
							}
						}
					}
					conn.SetReadDeadline(time.Time{}) // 清除deadline
					
				default:
					// 非阻塞检查连接状态 - 简单跳过
					time.Sleep(10 * time.Millisecond)
				}
			}
		}()
		
		logger.Println("Disconnected... Retrying in 3 seconds")
		time.Sleep(3 * time.Second)
	}
}

func main() {
	// 初始化日志
	initLogger()
	logger.Println("Server Monitor Client Starting...")
	
	// 设置信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	// 解析命令行参数
	config := ClientConfig{}
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "URL=") {
			config.URL = strings.TrimPrefix(arg, "URL=")
		} else if strings.HasPrefix(arg, "UUID=") {
			config.UUID = strings.TrimPrefix(arg, "UUID=")
		} else if strings.HasPrefix(arg, "Client_ID=") {
			config.ClientID = strings.TrimPrefix(arg, "Client_ID=")
		}
	}
	
	if config.URL == "" || config.UUID == "" || config.ClientID == "" {
		logger.Fatal("Missing required parameters: URL, UUID, Client_ID")
	}
	
	// 获取客户端IP信息
	priority, countryCode, emoji, ipv4, ipv6 := getClientIP()
	
	// 获取服务器信息
	server, port := getServerIP(config.URL, ipv4, ipv6)
	if server == "" || port == 0 {
		logger.Fatal("Failed to get server information")
	}
	
	logger.Printf("IP: %s,%s SERVER: %s:%d UUID: %s", ipv4, ipv6, server, port, config.UUID)
	
	// 启动主监控循环
	go monitorVPS(config, priority, countryCode, emoji, ipv4, ipv6, server, port)
	
	// 启动IP更新goroutine
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		
		for {
			select {
			case <-globalCtx.Done():
				logger.Println("IP update goroutine stopping...")
				return
			case <-ticker.C:
				newPriority, newCountryCode, newEmoji, newIPv4, newIPv6 := getClientIP()
				if newIPv4 != "" || newIPv6 != "" || newPriority != "" {
					priority, countryCode, emoji, ipv4, ipv6 = newPriority, newCountryCode, newEmoji, newIPv4, newIPv6
					logger.Println("IP address updated successfully")
				} else {
					logger.Println("Failed to update IP address")
				}
			}
		}
	}()
	
	// 等待信号
	<-sigChan
	logger.Println("Received shutdown signal, starting graceful shutdown...")
	
	// 取消所有goroutine
	globalCancel()
	
	// 等待所有goroutine结束，最多等待30秒
	done := make(chan struct{})
	go func() {
		globalWaitGroup.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		logger.Println("All goroutines stopped gracefully")
	case <-time.After(30 * time.Second):
		logger.Println("Timeout waiting for goroutines to stop, forcing exit")
	}
	
	logger.Println("Server Monitor Client stopped")
}

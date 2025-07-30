package collector

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// SystemInfo represents system information
type SystemInfo struct {
	Hostname     string                 `json:"hostname"`
	OS           string                 `json:"os"`
	Kernel       string                 `json:"kernel"`
	Architecture string                 `json:"architecture"`
	CPUInfo      CPUInfo                `json:"cpu_info"`
	MemoryInfo   MemoryInfo             `json:"memory_info"`
	DiskInfo     []DiskInfo             `json:"disk_info"`
	NetworkInfo  []NetworkInterface     `json:"network_info"`
	Uptime       time.Duration          `json:"uptime"`
	LoadAverage  LoadAverage            `json:"load_average"`
	Timestamp    time.Time              `json:"timestamp"`
}

// CPUInfo represents CPU information
type CPUInfo struct {
	Cores       int     `json:"cores"`
	ModelName   string  `json:"model_name"`
	UsagePercent float64 `json:"usage_percent"`
}

// MemoryInfo represents memory information  
type MemoryInfo struct {
	Total     uint64  `json:"total"`
	Available uint64  `json:"available"`
	Used      uint64  `json:"used"`
	UsagePercent float64 `json:"usage_percent"`
}

// DiskInfo represents disk information
type DiskInfo struct {
	Device     string  `json:"device"`
	Mountpoint string  `json:"mountpoint"`
	Total      uint64  `json:"total"`
	Used       uint64  `json:"used"`
	Available  uint64  `json:"available"`
	UsagePercent float64 `json:"usage_percent"`
}

// NetworkInterface represents network interface information
type NetworkInterface struct {
	Name      string `json:"name"`
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	BytesSent uint64 `json:"bytes_sent"`
	BytesRecv uint64 `json:"bytes_recv"`
}

// LoadAverage represents system load average
type LoadAverage struct {
	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
}

// SystemCollector collects system information
type SystemCollector struct{}

// NewSystemCollector creates a new system collector
func NewSystemCollector() *SystemCollector {
	return &SystemCollector{}
}

// Collect gathers current system information
func (sc *SystemCollector) Collect() (*SystemInfo, error) {
	info := &SystemInfo{
		Timestamp: time.Now(),
	}

	var err error
	
	// Get hostname
	info.Hostname, err = os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}

	// Get OS info
	info.OS = runtime.GOOS
	info.Architecture = runtime.GOARCH

	// Get kernel version
	info.Kernel, _ = sc.getKernelVersion()

	// Get CPU info
	info.CPUInfo, _ = sc.getCPUInfo()

	// Get memory info
	info.MemoryInfo, _ = sc.getMemoryInfo()

	// Get disk info
	info.DiskInfo, _ = sc.getDiskInfo()

	// Get network info
	info.NetworkInfo, _ = sc.getNetworkInfo()

	// Get uptime
	info.Uptime, _ = sc.getUptime()

	// Get load average
	info.LoadAverage, _ = sc.getLoadAverage()

	return info, nil
}

// getKernelVersion reads kernel version from /proc/version
func (sc *SystemCollector) getKernelVersion() (string, error) {
	content, err := os.ReadFile("/proc/version")
	if err != nil {
		return "", err
	}
	
	parts := strings.Fields(string(content))
	if len(parts) >= 3 {
		return parts[2], nil
	}
	return string(content), nil
}

// getCPUInfo reads CPU information from /proc/cpuinfo and /proc/stat
func (sc *SystemCollector) getCPUInfo() (CPUInfo, error) {
	info := CPUInfo{}
	
	// Get CPU count
	info.Cores = runtime.NumCPU()
	
	// Read CPU model from /proc/cpuinfo
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return info, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "model name") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				info.ModelName = strings.TrimSpace(parts[1])
				break
			}
		}
	}

	// Calculate CPU usage (simplified)
	info.UsagePercent, _ = sc.getCPUUsage()
	
	return info, nil
}

// getCPUUsage calculates CPU usage percentage
func (sc *SystemCollector) getCPUUsage() (float64, error) {
	// Read /proc/stat twice with interval to calculate usage
	stat1, err := sc.readProcStat()
	if err != nil {
		return 0, err
	}
	
	time.Sleep(100 * time.Millisecond)
	
	stat2, err := sc.readProcStat()
	if err != nil {
		return 0, err
	}
	
	// Calculate CPU usage percentage
	total1 := stat1.user + stat1.nice + stat1.system + stat1.idle + stat1.iowait + stat1.irq + stat1.softirq
	total2 := stat2.user + stat2.nice + stat2.system + stat2.idle + stat2.iowait + stat2.irq + stat2.softirq
	
	totalDiff := total2 - total1
	idleDiff := stat2.idle - stat1.idle
	
	if totalDiff == 0 {
		return 0, nil
	}
	
	return float64(totalDiff-idleDiff) / float64(totalDiff) * 100, nil
}

type cpuStat struct {
	user, nice, system, idle, iowait, irq, softirq uint64
}

// readProcStat reads CPU statistics from /proc/stat
func (sc *SystemCollector) readProcStat() (cpuStat, error) {
	var stat cpuStat
	
	file, err := os.Open("/proc/stat")
	if err != nil {
		return stat, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 8 && fields[0] == "cpu" {
			values := make([]uint64, 7)
			for i := 1; i <= 7; i++ {
				values[i-1], _ = strconv.ParseUint(fields[i], 10, 64)
			}
			stat.user = values[0]
			stat.nice = values[1]
			stat.system = values[2]
			stat.idle = values[3]
			stat.iowait = values[4]
			stat.irq = values[5]
			stat.softirq = values[6]
		}
	}
	
	return stat, nil
}

// getMemoryInfo reads memory information from /proc/meminfo
func (sc *SystemCollector) getMemoryInfo() (MemoryInfo, error) {
	info := MemoryInfo{}
	
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return info, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	memInfo := make(map[string]uint64)
	
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			key := strings.TrimSuffix(parts[0], ":")
			value, _ := strconv.ParseUint(parts[1], 10, 64)
			if len(parts) > 2 && parts[2] == "kB" {
				value *= 1024 // Convert kB to bytes
			}
			memInfo[key] = value
		}
	}
	
	info.Total = memInfo["MemTotal"]
	info.Available = memInfo["MemAvailable"]
	info.Used = info.Total - info.Available
	
	if info.Total > 0 {
		info.UsagePercent = float64(info.Used) / float64(info.Total) * 100
	}
	
	return info, nil
}

// getDiskInfo reads disk information (simplified implementation)
func (sc *SystemCollector) getDiskInfo() ([]DiskInfo, error) {
	// This is a simplified implementation
	// In production, you'd want to parse /proc/mounts and use syscalls
	return []DiskInfo{}, nil
}

// getNetworkInfo reads network interface information
func (sc *SystemCollector) getNetworkInfo() ([]NetworkInterface, error) {
	// This is a simplified implementation
	// In production, you'd parse /proc/net/dev and use netlink
	return []NetworkInterface{}, nil
}

// getUptime reads system uptime from /proc/uptime
func (sc *SystemCollector) getUptime() (time.Duration, error) {
	content, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	
	fields := strings.Fields(string(content))
	if len(fields) > 0 {
		seconds, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(seconds * float64(time.Second)), nil
	}
	
	return 0, fmt.Errorf("invalid uptime format")
}

// getLoadAverage reads load average from /proc/loadavg
func (sc *SystemCollector) getLoadAverage() (LoadAverage, error) {
	var load LoadAverage
	
	content, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return load, err
	}
	
	fields := strings.Fields(string(content))
	if len(fields) >= 3 {
		load.Load1, _ = strconv.ParseFloat(fields[0], 64)
		load.Load5, _ = strconv.ParseFloat(fields[1], 64)
		load.Load15, _ = strconv.ParseFloat(fields[2], 64)
	}
	
	return load, nil
} 
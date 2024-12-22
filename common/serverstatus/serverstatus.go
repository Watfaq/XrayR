// Package serverstatus generate the server system status
package serverstatus

import (
	"errors"
	"fmt"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

// GetSystemInfo get the system info of a given periodic
func GetSystemInfo() (c, m, d float64, up uint64, err error) {
	errorString := ""

	cpuPercent, err := cpu.Percent(0, false)
	// Check if cpuPercent is empty
	if len(cpuPercent) > 0 && err == nil {
		c = cpuPercent[0]
	} else {
		c = 0
		errorString += fmt.Sprintf("get cpu usage failed: %s ", err)
	}

	memUsage, err := mem.VirtualMemory()
	if err != nil {
		errorString += fmt.Sprintf("get mem usage failed: %s ", err)
	} else {
		m = memUsage.UsedPercent
	}

	diskUsage, err := disk.Usage("/")
	if err != nil {
		errorString += fmt.Sprintf("get disk usage failed: %s ", err)
	} else {
		d = diskUsage.UsedPercent
	}

	uptime, err := host.Uptime()
	if err != nil {
		errorString += fmt.Sprintf("get uptime failed: %s ", err)
	} else {
		up = uptime
	}

	if errorString != "" {
		err = errors.New(errorString)
	}

	return c, m, d, up, err
}

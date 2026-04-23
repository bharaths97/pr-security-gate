package main

import "os/exec"

func exportReport(cmd string) *exec.Cmd {
	return exec.Command("sh", "-c", cmd)
}

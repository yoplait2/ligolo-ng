//go:build windows

package rssh

import (
	"fmt"
	"io"
	"log"
	"os/exec"

	"github.com/gliderlabs/ssh"
)

// createPty on Windows spawns the shell without a real PTY.
// For full PTY support on Windows, pass the path to ssh-shellhost.exe as shell.
func createPty(s ssh.Session, shell string) {
	ptyReq, _, _ := s.Pty()
	cmd := exec.CommandContext(s.Context(), shell)
	cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))

	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Println("[rssh] StdinPipe error:", err)
		s.Exit(255)
		return
	}
	go func() { io.Copy(stdin, s); s.Close() }()
	cmd.Stdout = s
	cmd.Stderr = s

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case err := <-done:
		if err != nil {
			log.Println("[rssh] Session ended with error:", err)
			s.Exit(255)
			return
		}
		s.Exit(cmd.ProcessState.ExitCode())
	case <-s.Context().Done():
		log.Printf("[rssh] Session terminated: %s", s.Context().Err())
	}
}

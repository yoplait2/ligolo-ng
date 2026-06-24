//go:build !windows

package rssh

import (
	"fmt"
	"io"
	"log"
	"os/exec"
	"os/user"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
)

func createPty(s ssh.Session, shell string) {
	ptyReq, winCh, _ := s.Pty()
	cmd := exec.CommandContext(s.Context(), shell)
	cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	if u, err := user.Current(); err == nil {
		cmd.Env = append(cmd.Env, fmt.Sprintf("HOME=%s", u.HomeDir))
	}

	f, err := pty.Start(cmd)
	if err != nil {
		log.Fatalln("[rssh] Could not start shell:", err)
	}

	go func() {
		for win := range winCh {
			pty.Setsize(f, &pty.Winsize{Rows: uint16(win.Height), Cols: uint16(win.Width)})
		}
	}()
	go func() { io.Copy(f, s); s.Close() }()
	go func() { io.Copy(s, f); s.Close() }()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

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

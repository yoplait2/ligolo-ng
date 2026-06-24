package rssh

import (
	"io"
	"log"
	"os/exec"

	"github.com/gliderlabs/ssh"
)

func sessionHandler(shell string) ssh.Handler {
	return func(s ssh.Session) {
		log.Printf("[rssh] Login from %s@%s", s.User(), s.RemoteAddr())
		_, _, isPty := s.Pty()

		switch {
		case isPty:
			log.Println("[rssh] PTY requested")
			createPty(s, shell)

		case len(s.Command()) > 0:
			log.Printf("[rssh] Command: %q", s.RawCommand())
			cmd := exec.CommandContext(s.Context(), s.Command()[0], s.Command()[1:]...)
			stdin, err := cmd.StdinPipe()
			if err != nil {
				log.Println("[rssh] StdinPipe error:", err)
				s.Exit(255)
				return
			}
			go func() {
				io.Copy(stdin, s)
				s.Close()
			}()
			cmd.Stdout = s
			cmd.Stderr = s

			done := make(chan error, 1)
			go func() { done <- cmd.Run() }()

			select {
			case err := <-done:
				if err != nil {
					log.Println("[rssh] Command failed:", err)
					s.Exit(255)
					return
				}
				s.Exit(cmd.ProcessState.ExitCode())
			case <-s.Context().Done():
				log.Printf("[rssh] Session terminated: %s", s.Context().Err())
			}

		default:
			log.Println("[rssh] No PTY, no command — waiting for port-forwarding")
			<-s.Context().Done()
			log.Printf("[rssh] Session terminated: %s", s.Context().Err())
		}
	}
}

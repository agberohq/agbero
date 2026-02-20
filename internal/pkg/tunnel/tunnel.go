package tunnel

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/olekukonko/ll"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

const (
	DefaultSSHPort    = "22"
	DefaultSSHUser    = "root"
	DefaultTunnelPort = "7510"
)

type Config struct {
	Server        string
	User          string
	KeyPath       string
	UsePassword   bool
	LocalHost     string
	LocalPort     string
	RemoteHost    string
	RemotePort    string
	AutoReconnect bool
	MaxRetries    int
	RetryDelay    time.Duration
}

type Tunnel struct {
	log        *ll.Logger
	cfg        Config
	sshConfig  *ssh.ClientConfig
	stopChan   chan struct{}
	localAddr  string
	remoteAddr string
	sshAddr    string
}

func New(log *ll.Logger, cfg Config) (*Tunnel, error) {
	if cfg.LocalHost == "" {
		cfg.LocalHost = "127.0.0.1"
	}
	if cfg.LocalPort == "" {
		cfg.LocalPort = DefaultTunnelPort
	}

	t := &Tunnel{
		log:      log.Namespace("tunnel"),
		cfg:      cfg,
		stopChan: make(chan struct{}),
	}

	if err := t.configureSSH(); err != nil {
		return nil, err
	}

	t.localAddr = fmt.Sprintf("%s:%s", cfg.LocalHost, cfg.LocalPort)
	t.remoteAddr = fmt.Sprintf("%s:%s", cfg.RemoteHost, cfg.RemotePort)

	sshHost := cfg.Server
	sshPort := DefaultSSHPort
	if host, port, err := net.SplitHostPort(cfg.Server); err == nil {
		sshHost = host
		sshPort = port
	}
	t.sshAddr = fmt.Sprintf("%s:%s", sshHost, sshPort)

	return t, nil
}

func (t *Tunnel) configureSSH() error {
	var authMethods []ssh.AuthMethod

	if auth, err := t.getAgentAuth(); err == nil {
		authMethods = append(authMethods, auth)
		t.log.Debug("ssh agent authentication enabled")
	}

	if t.cfg.KeyPath != "" {
		if auth, err := t.getKeyAuth(t.cfg.KeyPath); err == nil {
			authMethods = append(authMethods, auth)
		} else {
			return fmt.Errorf("failed to load key %s: %w", t.cfg.KeyPath, err)
		}
	} else {
		for _, key := range t.findDefaultKeys() {
			if auth, err := t.getKeyAuth(key); err == nil {
				authMethods = append(authMethods, auth)
			}
		}
	}

	if t.cfg.UsePassword {
		if auth, err := t.getPasswordAuth(); err == nil {
			authMethods = append(authMethods, auth)
		} else {
			return err
		}
	}

	if len(authMethods) == 0 {
		return fmt.Errorf("no valid authentication methods found")
	}

	t.sshConfig = &ssh.ClientConfig{
		User:            t.cfg.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	return nil
}

func (t *Tunnel) getAgentAuth() (ssh.AuthMethod, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, fmt.Errorf("no socket")
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeysCallback(agent.NewClient(conn).Signers), nil
}

func (t *Tunnel) getKeyAuth(path string) (ssh.AuthMethod, error) {
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, path[2:])
	}

	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		if strings.Contains(err.Error(), "passphrase") || strings.Contains(err.Error(), "encrypted") {
			fmt.Printf("Enter passphrase for %s: ", path)
			pass, _ := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, pass)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	return ssh.PublicKeys(signer), nil
}

func (t *Tunnel) getPasswordAuth() (ssh.AuthMethod, error) {
	if pwd := os.Getenv("SSH_PASSWORD"); pwd != "" {
		return ssh.Password(pwd), nil
	}
	fmt.Print("Enter SSH password: ")
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	return ssh.Password(string(pass)), nil
}

func (t *Tunnel) findDefaultKeys() []string {
	home, _ := os.UserHomeDir()
	sshDir := filepath.Join(home, ".ssh")
	candidates := []string{"id_ed25519", "id_rsa", "id_ecdsa"}
	var found []string
	for _, c := range candidates {
		path := filepath.Join(sshDir, c)
		if _, err := os.Stat(path); err == nil {
			found = append(found, path)
		}
	}
	return found
}

func (t *Tunnel) Start() error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		close(t.stopChan)
	}()

	t.log.Fields(
		"local", t.localAddr,
		"remote", t.remoteAddr,
		"via", t.sshAddr,
	).Info("starting tunnel")

	return t.loop()
}

func (t *Tunnel) loop() error {
	retries := 0
	for {
		select {
		case <-t.stopChan:
			return nil
		default:
			if err := t.forward(); err != nil {
				t.log.Fields("err", err).Error("connection failed")
				if !t.cfg.AutoReconnect {
					return err
				}
				if t.cfg.MaxRetries >= 0 && retries >= t.cfg.MaxRetries {
					return fmt.Errorf("max retries exceeded")
				}
				retries++
				time.Sleep(t.cfg.RetryDelay)
				continue
			}
			retries = 0
		}
	}
}

func (t *Tunnel) forward() error {
	client, err := ssh.Dial("tcp", t.sshAddr, t.sshConfig)
	if err != nil {
		return err
	}
	defer client.Close()

	t.log.Info("ssh connected")

	listener, err := net.Listen("tcp", t.localAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	t.log.Info("tunnel listening")

	for {
		select {
		case <-t.stopChan:
			return nil
		default:
			if l, ok := listener.(*net.TCPListener); ok {
				_ = l.SetDeadline(time.Now().Add(1 * time.Second))
			}
			conn, err := listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return err
			}
			go t.pipe(conn, client)
		}
	}
}

func (t *Tunnel) pipe(local net.Conn, client *ssh.Client) {
	defer local.Close()
	remote, err := client.Dial("tcp", t.remoteAddr)
	if err != nil {
		t.log.Fields("err", err).Error("remote dial failed")
		return
	}
	defer remote.Close()

	done := make(chan struct{}, 2)
	copy := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}

	go copy(remote, local)
	go copy(local, remote)
	<-done
}

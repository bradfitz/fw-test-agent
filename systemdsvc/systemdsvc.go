package systemdsvc

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func HandleAction(action, service string, args ...string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("not root")
	}
	if !strings.HasSuffix(service, ".service") {
		service += ".service"
	}
	switch action {
	case "install":
		systemctl("stop", service)
		file := "/etc/systemd/system/" + service
		was, _ := os.ReadFile(file)
		want, err := unit(service, strings.Join(args, " "))
		if err != nil {
			return err
		}
		if !bytes.Equal(was, want) {
			systemctl("stop", service)
			systemctl("disable", service)
			if err := os.WriteFile(file, want, 0644); err != nil {
				return err
			}
			if err := systemctl("enable", file); err != nil {
				return fmt.Errorf("enable: %w", err)
			}
		}
		return systemctl("start", service)
	case "uninstall":
		systemctl("stop", service)
		systemctl("disable", service)
		return nil
	default:
		return fmt.Errorf("unknown systemdsvc action %q", action)
	}
}

func systemctl(action, arg string) error {
	return exec.Command("systemctl", action, arg).Run()
}

func unit(svc string, args string) ([]byte, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, `[Unit]
Description=%s
Wants=network-online.target
After=network-online.target

[Install]
WantedBy=multi-user.target

[Service]
ExecStart=%s %s
Restart=always
RestartSec=10s
`, svc, exe, args), nil
}

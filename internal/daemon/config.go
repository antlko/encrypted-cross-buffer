package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ConfigFile is the name of the runtime config in the config dir.
const ConfigFile = "config.json"

// Sync modes.
const (
	ModeBoth        = "both"
	ModeSendOnly    = "send-only"
	ModeReceiveOnly = "receive-only"
	ModePaused      = "paused"
)

// Defaults.
const (
	DefaultMaxText  = 8 << 20
	DefaultMaxImage = 8 << 20
)

// Config is the runtime configuration; the daemon re-reads it when it changes.
type Config struct {
	Mode          string `json:"mode"`
	MaxTextBytes  int64  `json:"max_text_bytes"`
	MaxImageBytes int64  `json:"max_image_bytes"`
}

// DefaultConfig returns the defaults.
func DefaultConfig() Config {
	return Config{Mode: ModeBoth, MaxTextBytes: DefaultMaxText, MaxImageBytes: DefaultMaxImage}
}

// ValidMode reports whether m is a known mode.
func ValidMode(m string) bool {
	switch m {
	case ModeBoth, ModeSendOnly, ModeReceiveOnly, ModePaused:
		return true
	}
	return false
}

func (c Config) validate() error {
	if !ValidMode(c.Mode) {
		return fmt.Errorf("invalid mode %q (want both, send-only, receive-only or paused)", c.Mode)
	}
	if c.MaxTextBytes <= 0 || c.MaxImageBytes <= 0 {
		return fmt.Errorf("max_text_bytes and max_image_bytes must be positive")
	}
	return nil
}

func (c Config) canSend() bool    { return c.Mode == ModeBoth || c.Mode == ModeSendOnly }
func (c Config) canReceive() bool { return c.Mode == ModeBoth || c.Mode == ModeReceiveOnly }

// ErrBrokenConfig means config.json exists but cannot be parsed or is invalid.
// Callers must NOT fall back to the defaults (mode "both") in that case: a
// corrupt file could otherwise silently turn "paused" into full sync.
var ErrBrokenConfig = errors.New("config.json is invalid")

// LoadConfig reads dir/config.json; a missing file yields the defaults and
// missing fields keep their defaults. A file that exists but is unreadable or
// invalid yields an error wrapping ErrBrokenConfig (the returned Config is then
// meaningless and must not be used).
func LoadConfig(dir string) (Config, error) {
	c := DefaultConfig()
	path := filepath.Join(dir, ConfigFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("%w: %s: %v", ErrBrokenConfig, ConfigFile, err)
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("%w: %s: %v", ErrBrokenConfig, ConfigFile, err)
	}
	if err := c.validate(); err != nil {
		return Config{}, fmt.Errorf("%w: %s: %v", ErrBrokenConfig, ConfigFile, err)
	}
	return c, nil
}

// SaveConfig writes dir/config.json atomically (0600).
func SaveConfig(dir string, c Config) error {
	if err := c.validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, ConfigFile))
}

// SetMode updates only the mode in dir/config.json. If the existing file is
// broken it returns an error wrapping ErrBrokenConfig and leaves the file
// alone; use RepairMode to replace it explicitly.
func SetMode(dir, mode string) error {
	c, err := LoadConfig(dir)
	if err != nil {
		return fmt.Errorf("%w\nrun `ecb mode %s` again to replace it with a fresh config, or fix %s by hand",
			err, mode, filepath.Join(dir, ConfigFile))
	}
	c.Mode = mode
	return SaveConfig(dir, c)
}

// RepairMode replaces a broken config.json with the defaults plus mode. The
// old file is kept next to it as config.json.bad.
func RepairMode(dir, mode string) error {
	c := DefaultConfig()
	c.Mode = mode
	if err := c.validate(); err != nil {
		return err
	}
	path := filepath.Join(dir, ConfigFile)
	if err := os.Rename(path, path+".bad"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return SaveConfig(dir, c)
}

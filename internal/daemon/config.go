package daemon

import (
	"encoding/json"
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

// LoadConfig reads dir/config.json; a missing file yields the defaults and
// missing fields keep their defaults.
func LoadConfig(dir string) (Config, error) {
	c := DefaultConfig()
	b, err := os.ReadFile(filepath.Join(dir, ConfigFile))
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return DefaultConfig(), fmt.Errorf("%s: %w", ConfigFile, err)
	}
	if err := c.validate(); err != nil {
		return DefaultConfig(), fmt.Errorf("%s: %w", ConfigFile, err)
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

// SetMode updates only the mode in dir/config.json.
func SetMode(dir, mode string) error {
	c, err := LoadConfig(dir)
	if err != nil {
		c = DefaultConfig() // a broken file is replaced by a valid one
	}
	c.Mode = mode
	return SaveConfig(dir, c)
}

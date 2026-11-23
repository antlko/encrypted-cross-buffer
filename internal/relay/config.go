package relay

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Rate is a token bucket: Burst tokens, one refilled every Every.
type Rate struct {
	Burst int
	Every time.Duration
}

// RateLimits are the (in-memory, per process) limiter settings.
type RateLimits struct {
	EnrollFail Rate // per IP, consumed only by failed enroll attempts
	AuthIP     Rate // per IP: /v1/auth/*
	AuthDevice Rate // per device key: /v1/auth/token
	Pair       Rate // per IP: unauthenticated pairing mailbox endpoints
	Items      Rate // per device: POST /v1/items
	PairBurn   Rate // per IP: mailbox-burning requests (DELETE, full-mailbox POST)
}

// DefaultRateLimits are the production defaults.
func DefaultRateLimits() RateLimits {
	return RateLimits{
		EnrollFail: Rate{5, time.Minute},
		AuthIP:     Rate{30, 500 * time.Millisecond},
		AuthDevice: Rate{10, time.Second},
		Pair:       Rate{30, 200 * time.Millisecond},
		Items:      Rate{30, 500 * time.Millisecond},
		PairBurn:   Rate{10, 6 * time.Second}, // ~10 burns per minute
	}
}

// Config is the relay configuration.
type Config struct {
	Addr              string
	DataDir           string
	EnrollToken       string
	MaxItemBytes      int64
	ItemTTL           time.Duration
	TrustProxyHeaders bool

	Limits        RateLimits
	SweepInterval time.Duration // default 30s
	PingInterval  time.Duration // server->client websocket ping, default 25s
	Now           func() time.Time
}

// MinEnrollTokenLen is the minimum length of ECB_ENROLL_TOKEN.
const MinEnrollTokenLen = 16

// ConfigFromEnv builds a Config from environment variables (getenv is
// os.Getenv in production). The error text never contains the token.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	c := Config{
		Addr:         ":8080",
		DataDir:      "/data",
		MaxItemBytes: 32 << 20,
		ItemTTL:      10 * time.Minute,
		Limits:       DefaultRateLimits(),
	}
	if v := getenv("ECB_ADDR"); v != "" {
		c.Addr = v
	}
	if v := getenv("ECB_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	c.EnrollToken = getenv("ECB_ENROLL_TOKEN")
	if len(c.EnrollToken) < MinEnrollTokenLen {
		return c, fmt.Errorf("ECB_ENROLL_TOKEN is required and must be at least %d characters", MinEnrollTokenLen)
	}
	if v := getenv("ECB_MAX_ITEM_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1024 {
			return c, errors.New("ECB_MAX_ITEM_BYTES must be an integer >= 1024")
		}
		c.MaxItemBytes = n
	}
	if v := getenv("ECB_ITEM_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return c, errors.New("ECB_ITEM_TTL must be a positive duration such as 10m")
		}
		c.ItemTTL = d
	}
	if v := getenv("ECB_TRUST_PROXY_HEADERS"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return c, errors.New("ECB_TRUST_PROXY_HEADERS must be true or false")
		}
		c.TrustProxyHeaders = b
	}
	return c, nil
}

func (c *Config) defaults() {
	if c.MaxItemBytes <= 0 {
		c.MaxItemBytes = 32 << 20
	}
	if c.ItemTTL <= 0 {
		c.ItemTTL = 10 * time.Minute
	}
	if c.SweepInterval <= 0 {
		c.SweepInterval = 30 * time.Second
	}
	if c.PingInterval <= 0 {
		c.PingInterval = 25 * time.Second
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Limits == (RateLimits{}) {
		c.Limits = DefaultRateLimits()
	}
	if c.Limits.PairBurn == (Rate{}) {
		c.Limits.PairBurn = DefaultRateLimits().PairBurn
	}
}

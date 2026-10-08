package cache

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Status represents the health status of the cache dependency.
type Status struct {
	State     string  `json:"status"` // UP or DOWN
	LatencyMS float64 `json:"latency_ms,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// Client manages Redis connection health.
type Client struct {
	addr string
}

// NewClient parses the redis connection string and creates a Redis client.
func NewClient(rawURL string) (*Client, error) {
	// Handle redis://host:port or host:port
	addr := rawURL
	if strings.HasPrefix(rawURL, "redis://") {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return nil, fmt.Errorf("invalid REDIS_URL: %w", err)
		}
		addr = parsed.Host
	}

	if !strings.Contains(addr, ":") {
		addr = addr + ":6379"
	}

	return &Client{
		addr: addr,
	}, nil
}

// Ping connects to Redis, sends standard wire PING, verifies +PONG, and measures latency.
func (c *Client) Ping(ctx context.Context) Status {
	start := time.Now()
	timeout := 2 * time.Second

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return Status{
			State: "DOWN",
			Error: err.Error(),
		}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Send Redis protocol PING
	if _, err := conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		return Status{
			State: "DOWN",
			Error: fmt.Sprintf("write ping failed: %v", err),
		}
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return Status{
			State: "DOWN",
			Error: fmt.Sprintf("read pong failed: %v", err),
		}
	}

	if !strings.HasPrefix(line, "+PONG") {
		return Status{
			State: "DOWN",
			Error: fmt.Sprintf("unexpected response from redis: %q", strings.TrimSpace(line)),
		}
	}

	latency := float64(time.Since(start).Microseconds()) / 1000.0
	return Status{
		State:     "UP",
		LatencyMS: latency,
	}
}

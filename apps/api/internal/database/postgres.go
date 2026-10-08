package database

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Status represents the health status of a database dependency.
type Status struct {
	State     string  `json:"status"` // UP or DOWN
	LatencyMS float64 `json:"latency_ms,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// Client manages database health and operations.
type Client struct {
	addr string
}

// NewClient parses the postgres connection string and creates a database client.
func NewClient(rawURL string) (*Client, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid DATABASE_URL: %w", err)
	}

	hostPort := parsed.Host
	if !strings.Contains(hostPort, ":") {
		hostPort = hostPort + ":5432"
	}

	return &Client{
		addr: hostPort,
	}, nil
}

// Ping checks whether the PostgreSQL database is reachable and measures latency.
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

	latency := float64(time.Since(start).Microseconds()) / 1000.0
	return Status{
		State:     "UP",
		LatencyMS: latency,
	}
}

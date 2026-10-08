import defaultConfig from '../default.json';

export interface AppConfig {
  app: {
    name: string;
    version: string;
    tagline: string;
    env: string;
  };
  server: {
    port: number;
    read_timeout_seconds: number;
    write_timeout_seconds: number;
    idle_timeout_seconds: number;
    cors_allowed_origins: string[];
  };
  database: {
    max_open_conns: number;
    max_idle_conns: number;
    conn_max_lifetime_minutes: number;
  };
  redis: {
    connect_timeout_seconds: number;
    read_timeout_seconds: number;
    write_timeout_seconds: number;
  };
  safety: {
    rate_limit_requests_per_second: number;
    rate_limit_burst: number;
    block_private_ips: boolean;
    max_scan_timeout_seconds: number;
  };
  services: {
    browser_worker_url: string;
  };
}

export function getConfig(): AppConfig {
  return defaultConfig as AppConfig;
}

export default defaultConfig;

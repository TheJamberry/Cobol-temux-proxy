# COBOL Telnet Proxy

This repository packages a small tmux based telnet proxy that can be installed on a
Linux host to multiplex access to a legacy COBOL system.  The tree mirrors the
layout that should end up on the target machine (configuration under
`/etc/cobol-proxy`, executables under `/usr/local/bin`, and a systemd service
unit).

## Features

* Async Python proxy that bridges a raw telnet client to a dedicated tmux
  session per source IP.
* Optional IP binding pool so that clients can receive a stable source
  address when the backend requires it.
* `cobol` helper CLI for checking running sessions and toggling options.
* Systemd unit to run the proxy as a service.

## Requirements

Install the following packages on your Linux machine (examples are for Debian/Ubuntu):

```bash
sudo apt-get install python3 tmux telnet socat
```

The proxy itself only uses Python standard library modules.

## Installation

1. Clone the repository and copy the files to their final locations:

   ```bash
   git clone https://example.com/Cobol-temux-proxy.git
   sudo rsync -a Cobol-temux-proxy/etc/ /etc/
   sudo rsync -a Cobol-temux-proxy/usr/ /usr/
   ```

2. Reload systemd so it sees the new unit and enable the service:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now cobol-ip-proxy.service
   ```

3. Verify the proxy is running:

   ```bash
   sudo systemctl status cobol-ip-proxy.service
   ```

The helper CLI is available as `sudo cobol list`.

## Configuration

Edit `/etc/cobol-proxy/config.yml` to match your environment.  The default file
is created automatically the first time the `cobol` helper runs.  Relevant keys:

* `listen_host`, `listen_port` – the proxy listening address/port.
* `cobol_host`, `cobol_port` – backend COBOL system connection.
* `term_type` – TERM exported for the telnet session.
* `ip_bind` – enable sticky source IP assignment (`true`/`false`).
* `ip_pool_cidr` – CIDR pool that will be assigned to clients when `ip_bind`
  is enabled.
* `bind_iface` – interface where temporary addresses are created.
* `admin_ips` – list of IPs that should detach other viewers when connecting.

Whenever you change `ip_bind` or `ip_pool_cidr` through the `cobol` CLI, the
proxy service is restarted automatically.

## Usage Tips

* `sudo cobol list` – show the currently known source IPs and tmux status.
* `sudo cobol control <src_ip>` – attach to the tmux session for that client.
* `sudo cobol ip-bind on|off` – enable/disable source address binding.
* `sudo cobol ip-pool <CIDR>` – configure the binding pool.

Sessions and allocated IPs are tracked in `/etc/cobol-proxy/sessions.csv`.

## Troubleshooting

* Ensure `tmux` is installed and accessible as `/usr/bin/tmux`.  You can
  override the location by exporting `TMUX_BIN` before calling `cobol`.
* When using binding, verify the host interface allows secondary addresses and
  that the account has permission to call `/sbin/ip`.
* Check `/var/log/syslog` or `journalctl -u cobol-ip-proxy` for runtime errors.

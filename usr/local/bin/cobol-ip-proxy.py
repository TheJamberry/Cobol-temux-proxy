#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import asyncio, os, pty, subprocess, termios, tty, signal, ipaddress, shlex, json, re, sys, errno, logging
from pathlib import Path
from logging.handlers import SysLogHandler

def _parse_level(s: str, default: int) -> int:
    if not s:
        return default
    s = s.strip().upper()
    return getattr(logging, s, default)

def setup_logging(default_level: str = "INFO"):
    """
    Logging goes to stdout/stderr so systemd/journald captures it.
    Set runtime verbosity via env var: COBOL_PROXY_LOG_LEVEL=DEBUG|INFO|WARNING|ERROR
    (requires service restart to take effect).
    """
    level = _parse_level(os.environ.get("COBOL_PROXY_LOG_LEVEL", default_level), logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    # Clear any pre-existing handlers (e.g., when running under some reloaders)
    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    sh.setLevel(level)
    root.addHandler(sh)

    return logging.getLogger("cobol-ip-proxy")

log = setup_logging()
# ---------- Paths & config ----------
ETC = Path("/etc/cobol-proxy")
CFG = ETC / "config.yml"
SESS = ETC / "sessions.csv"  # "src_ip,allocated_pool_ip"

# Named tmux server so admins can see/control it.
TMUX_BIN = "/usr/bin/tmux"
TMUX_ARGS = ["-L", "cobol"]

# ---------- Simple config helpers ----------
# def read_yaml(path:Path)->dict:
#     if not path.exists(): return {}
#     out={}
#     for ln in path.read_text().splitlines():
#         ln=ln.strip()
#         if not ln or ln.startswith("#"): continue
#         if ":" in ln:
#             k,v=ln.split(":",1)
#             out[k.strip()] = v.strip().strip('"\'')
#     if "admin_ips" in out and str(out["admin_ips"]).startswith('['):
#         try: out["admin_ips"] = json.loads(out["admin_ips"])
#         except Exception: out["admin_ips"]=[]
#     return out

def read_yaml(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Config missing: {path}")
    out = {}
    for ln in path.read_text().splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if ":" in ln:
            k, v = ln.split(":", 1)
            out[k.strip()] = v.strip().strip('"\'')
    # admin_ips may be JSON array
    if "admin_ips" in out and out["admin_ips"].startswith("["):
        try:
            out["admin_ips"] = json.loads(out["admin_ips"])
        except Exception:
            out["admin_ips"] = []
    # ensure numeric types
    if "listen_port" in out:
        out["listen_port"] = int(out["listen_port"])
    if "cobol_port" in out:
        out["cobol_port"] = int(out["cobol_port"])
    return out

def load_sessions()->dict:
    d={}
    if SESS.exists():
        for ln in SESS.read_text().splitlines():
            ln=ln.strip()
            if not ln or ln.startswith("#"): continue
            ip,alloc = [x.strip() for x in ln.split(",",1)]
            d[ip]=alloc
    return d

def save_sessions(d:dict):
    lines=["# src_ip,allocated_pool_ip"]+[f"{k},{v}" for k,v in sorted(d.items())]
    SESS.write_text("\n".join(lines)+"\n")

# ---------- Subprocess helpers ----------
async def run(*args, check=False):
    proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out,err = await proc.communicate()
    if check and proc.returncode!=0:
        raise RuntimeError(f"{' '.join(args)} -> {proc.returncode}: {err.decode(errors='ignore')}")
    return out.decode(errors="ignore"), err.decode(errors="ignore"), proc.returncode

async def t(*args, check=False):
    return await run(TMUX_BIN, *TMUX_ARGS, *args, check=check)

async def tmux_has(name:str)->bool:
    *_, rc = await t("has-session","-t",name)
    return rc==0

# ---------- Telnet & terminal-reply filtering ----------
IAC=255; WILL=251; WONT=252; DO=253; DONT=254; SB=250; SE=240
def telnet_strip_iac(buf:bytes)->bytes:
    out=bytearray(); i=0; n=len(buf)
    while i<n:
        b=buf[i]
        if b!=IAC:
            out.append(b); i+=1; continue
        i+=1
        if i>=n: break
        cmd=buf[i]; i+=1
        if cmd in (WILL,WONT,DO,DONT):
            i+=1  # skip option
        elif cmd==SB:
            while i<n-1 and not (buf[i]==IAC and buf[i+1]==SE):
                i+=1
            i += 2 if i<n-1 else 0
        else:
            pass
    return bytes(out)

def strip_osc(buf: bytes) -> bytes:
    r"""Strip OSC: ESC ] ... (BEL | ESC \)"""
    out = bytearray(); i = 0; n = len(buf)
    while i < n:
        b = buf[i]
        if b == 0x1B and i + 1 < n and buf[i+1] == 0x5D:  # ESC ]
            i += 2
            while i < n:
                if buf[i] == 0x07:            # BEL
                    i += 1; break
                if buf[i] == 0x1B and i+1<n and buf[i+1]==0x5C:  # ESC \
                    i += 2; break
                i += 1
            continue
        out.append(b); i += 1
    return bytes(out)

def strip_da_dsr(buf: bytes) -> bytes:
    """
    Strip reply forms only:
      - DA replies:  ESC [ ? ... c
      - sec DA:      ESC [ > ... c
      - DSR replies: ESC [ 5 n, ESC [ 6 n
    Do NOT strip generic CSI so arrows/F-keys work.
    """
    out = bytearray()
    i = 0
    n = len(buf)
    while i < n:
        if buf[i] == 0x1B and i + 2 < n and buf[i + 1] == 0x5B:  # ESC [
            j = i + 2
            # handle DA / secondary DA replies
            if buf[j] in (0x3F, 0x3E):  # '?' or '>'
                j += 1
                # consume digits/semicolons until we hit a 'c'
                while j < n and buf[j] not in (0x63, 0x20, 0x1B) and (48 <= buf[j] <= 59):
                    j += 1
                if j < n and buf[j] == 0x63:
                    i = j + 1
                    continue
            # handle DSR 5n / 6n replies
            if buf[j:j+2] in (b'5', b'6'):
                j += 1
                if j < n and buf[j] == 0x6E:  # 'n'
                    i = j + 1
                    continue
        # keep normal bytes
        out.append(buf[i])
        i += 1
    return bytes(out)
    
def strip_bare_da(buf: bytes) -> bytes:
    """
    Some terminals (KoalaTerm) emit DA replies without the ESC[ introducer, e.g.:
      >41;1;0c   or   ?61;4;...;52c
    Remove those so they don't get 'typed' into COBOL.
    """
    out = bytearray()
    i = 0
    n = len(buf)
    while i < n:
        b = buf[i]
        if b in (0x3E, 0x3F):  # '>' or '?'
            j = i + 1
            # accept only digits and semicolons, then a trailing 'c'
            while j < n and (buf[j] == 0x3B or (0x30 <= buf[j] <= 0x39)):  # ';' or '0'-'9'
                j += 1
            if j < n and buf[j] == 0x63:  # 'c'
                # drop this whole reply
                i = j + 1
                continue
        out.append(b)
        i += 1
    return bytes(out)

# ---------- IP binding (optional) ----------
def ip_alias_present(iface:str, ip:str)->bool:
    try:
        out = subprocess.check_output(["ip","addr","show","dev",iface], text=True)
        return f" {ip}/" in out
    except Exception:
        return False

def add_ip_alias(iface:str, cidr:str, ip:str):
    prefix = str(ipaddress.ip_network(cidr, strict=False).prefixlen)
    if not ip_alias_present(iface, ip):
        subprocess.check_call(["ip","addr","add", f"{ip}/{prefix}", "dev", iface])

def next_free_ip(cidr:str, taken:set[str])->str|None:
    net = ipaddress.ip_network(cidr, strict=False)
    for host in net.hosts():
        ip=str(host)
        if ip not in taken:
            return ip
    return None

def maybe_allocate_src_ip_original(src_ip:str, cfg:dict, sessions:dict)->str|None:
    bind = cfg.get("ip_bind","false")
    if str(bind).lower() in ("false","0","off","no"): return None
    pool = cfg.get("ip_pool_cidr",""); iface = cfg.get("bind_iface","eth0")
    if not pool: return None
    if src_ip in sessions and sessions[src_ip]: return sessions[src_ip]
    taken=set(v for v in sessions.values() if v)
    ip = next_free_ip(pool, taken)
    if not ip: raise RuntimeError("IP pool exhausted")
    add_ip_alias(iface, pool, ip)
    sessions[src_ip]=ip; save_sessions(sessions)
    return ip

def maybe_allocate_src_ip(src_ip: str, cfg: dict, sessions: dict) -> str | None:
    # Always ensure src_ip is in sessions
    was_missing = src_ip not in sessions
    current_value = sessions.get(src_ip)

    # Determine what to store
    bind = cfg.get("ip_bind", "false")
    should_bind = str(bind).lower() in ("true", "1", "on", "yes")
    pool = cfg.get("ip_pool_cidr", "").strip()
    iface = cfg.get("bind_iface", "eth0")

    new_value = None

    if should_bind and pool:
        # IP binding enabled + pool defined ? allocate real alias
        taken = {v for v in sessions.values() if v}
        ip = next_free_ip(pool, taken)
        if not ip:
            raise RuntimeError("IP pool exhausted")
        add_ip_alias(iface, pool, ip)
        new_value = ip
    else:
        # No binding ? just record that we saw this src_ip (with empty alias)
        new_value = ""

    # Only update + save if value changed or was missing
    if was_missing or current_value != new_value:
        sessions[src_ip] = new_value
        save_sessions(sessions)

    return sessions[src_ip]


# ---------- tmux session mgmt ----------
# async def ensure_tmux_for_ip(src_ip:str, env:dict)->str:
#     name = re.sub(r"[^A-Za-z0-9_-]", "_", src_ip)
#     if await tmux_has(name): return name
#     env_export = " ".join(shlex.quote(f"{k}={v}") for k,v in env.items() if v)
#     cmd = f"{env_export} bash -lc 'clear; /usr/local/bin/cobol-telnet.sh'"
#     await t("new-session","-d","-s",name,cmd, check=True)
#     return name

# ---------- tmux session ----------
async def ensure_tmux_for_id(session_id: str, env: dict) -> str:
    name = re.sub(r"[^A-Za-z0-9_-]", "_", session_id)
    if await tmux_has(name):
        return name
    env_export = " ".join(shlex.quote(f"{k}={v}") for k, v in env.items() if v)
    cmd = f"{env_export} bash -lc 'clear; /usr/local/bin/cobol-telnet.sh'"
    await t("new-session", "-d", "-s", name, cmd, check=True)
    return name

async def tmux_detach_all(name:str):
    await t("detach","-a","-s",name)

# ---------- bridging ----------
def set_raw(fd): tty.setraw(fd, termios.TCSANOW)

async def bridge(reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter,
                 tmux_name: str,
                 detach_first: bool):

    if detach_first:
        await tmux_detach_all(tmux_name)

    async def tmux_attach_pipe():
        # (Your while True isn't really restarting because you return immediately,
        # but leaving it as-is since you said this was the only change.)
        while True:
            pid, master_fd = pty.fork()
            if pid == 0:
                os.environ.setdefault("TERM", "vt220")
                os.execl(TMUX_BIN, TMUX_BIN, *TMUX_ARGS, "attach", "-t", tmux_name)

            set_raw(master_fd)
            return master_fd, pid

    master_fd, child_pid = await tmux_attach_pipe()
    loop = asyncio.get_running_loop()
    attach_t0 = loop.time()

    tmux_reader = asyncio.StreamReader()
    proto = asyncio.StreamReaderProtocol(tmux_reader)

    # IMPORTANT: keep the transport so we can close it later
    transport, _ = await loop.connect_read_pipe(
        lambda: proto,
        os.fdopen(master_fd, 'rb', buffering=0)
    )
    tmux_writer = os.fdopen(master_fd, 'wb', buffering=0)

    async def c2s():
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                d = telnet_strip_iac(data)

                if loop.time() - attach_t0 < 0.3:
                    tmp = bytearray(); i = 0; n = len(d)
                    while i < n:
                        if d[i] == 0x1B:
                            i += 1
                            while i < n and not (0x40 <= d[i] <= 0x7E or d[i] == 0x07):
                                i += 1
                            if i < n: i += 1
                            continue
                        tmp.append(d[i]); i += 1
                    d = bytes(tmp)
                    d = strip_bare_da(d)

                d = strip_osc(d)
                d = strip_da_dsr(d)
                d = strip_bare_da(d)

                try:
                    tmux_writer.write(d)
                    tmux_writer.flush()
                except OSError:
                    break
        finally:
            # This ensures tmux attach exits when client side ends
            try:
                os.kill(child_pid, signal.SIGHUP)
            except Exception:
                pass

    async def s2c():
        try:
            while True:
                try:
                    out = await tmux_reader.read(4096)
                    if not out:
                        break
                    writer.write(out)
                    await writer.drain()
                except OSError:
                    break
        finally:
            try:
                writer.close()
            except Exception:
                pass

    try:
        await asyncio.gather(c2s(), s2c())
    finally:
        # Close transport/pty writer to release the fd cleanly
        try:
            transport.close()
        except Exception:
            pass

        try:
            tmux_writer.close()
        except Exception:
            pass

        # Reap the *specific* bridge child so it doesn't become <defunct>
        try:
            await asyncio.to_thread(os.waitpid, child_pid, 0)
        except ChildProcessError:
            pass
        except Exception:
            # Don't let cleanup exceptions break the caller
            pass

# ---------- server ----------
# async def handle_client(reader, writer):
#     src_ip = "0.0.0.0"
#     try:
#         peer = writer.get_extra_info("peername")
#         src_ip = peer[0] if peer else "0.0.0.0"

#         cfg = read_yaml(CFG); sessions = load_sessions()
#         admin_ips = cfg.get("admin_ips", [])
#         detach_first = src_ip in admin_ips

#         src_bind = maybe_allocate_src_ip(src_ip, cfg, sessions)
#         env = {
#             "COBOL_HOST": cfg.get("cobol_host","10.0.0.25"),
#             "COBOL_PORT": cfg.get("cobol_port","23"),
#             "TERM_TYPE": cfg.get("term_type","vt220"),
#             "SRC_IP": src_bind or ""
#         }

#         tmux_name = await ensure_tmux_for_ip(src_ip, env)
#         await bridge(reader, writer, tmux_name, detach_first)

#     except Exception:
#         try:
#             writer.write(b"\r\n[proxy error]\r\n"); await writer.drain()
#         except Exception: pass
#         writer.close()

async def handle_client(reader, writer, cfg: dict, env_name: str):
    src_ip = "0.0.0.0"
    peer = None
    started = asyncio.get_running_loop().time()
    try:
        peer = writer.get_extra_info("peername")
        src_ip = peer[0] if peer else "0.0.0.0"
        log.info("CONNECT env=%s src_ip=%s peer=%s", env_name.upper(), src_ip, peer)

        sessions = load_sessions()
        admin_ips = cfg.get("admin_ips", [])
        detach_first = src_ip in admin_ips

        src_bind = maybe_allocate_src_ip(src_ip, cfg, sessions)

        env_vars = {
            "COBOL_HOST": cfg.get("cobol_host", "10.0.0.25"),
            "COBOL_PORT": cfg.get("cobol_port", "23"),
            "TERM_TYPE": cfg.get("term_type", "vt220"),
            "SRC_IP": src_bind or "",
            "ENV": env_name.upper(),
        }

        tmux_name = await ensure_tmux_for_id(f"{env_name}_{src_ip}", env_vars)
        log.debug("SESSION env=%s src_ip=%s tmux=%s detach_first=%s src_bind=%s",
                  env_name.upper(), src_ip, tmux_name, detach_first, src_bind or "")

        await bridge(reader, writer, tmux_name, detach_first)

    except asyncio.CancelledError:
        # service shutdown / task cancellation
        log.info("DISCONNECT env=%s src_ip=%s reason=cancelled", env_name.upper(), src_ip)
        raise
    except Exception as e:
        log.exception("ERROR env=%s src_ip=%s peer=%s err=%s", env_name.upper(), src_ip, peer, e)
        try:
            writer.write(b"\r\n[proxy error]\r\n")
            await writer.drain()
        except Exception:
            pass
    finally:
        try:
            writer.close()
        except Exception:
            pass
        try:
            await writer.wait_closed()
        except Exception:
            pass
        dur = asyncio.get_running_loop().time() - started
        log.info("DISCONNECT env=%s src_ip=%s peer=%s duration=%.3fs",
                 env_name.upper(), src_ip, peer, dur)

# ---------- Server per config ----------
async def start_server_for_cfg(cfg_path: Path):
    cfg = read_yaml(cfg_path)
    # Optional per-config log level (requires restart of service/task to apply here)
    lvl = cfg.get("log_level", "")
    if lvl:
        logging.getLogger().setLevel(_parse_level(lvl, logging.getLogger().level))
    host = cfg.get("listen_host", "0.0.0.0")
    port = cfg.get("listen_port")
    env = cfg_path.stem.split("-", 1)[1]   # e.g. "dev", "qld"

    print(f"Starting {env.upper()} proxy on {host}:{port} ? {cfg['cobol_host']}:{cfg['cobol_port']}")
    log.info(f"Starting {env.upper()} proxy on {host}:{port} ? {cfg['cobol_host']}:{cfg['cobol_port']}")

    handler = lambda r, w: handle_client(r, w, cfg, env)
    server = await asyncio.start_server(handler, host, port, limit=1 << 15)

    async with server:
        await server.serve_forever()

# async def main():
#     cfg = read_yaml(CFG)
#     host = cfg.get("listen_host","0.0.0.0")
#     port = int(cfg.get("listen_port","2323"))
#     server = await asyncio.start_server(handle_client, host, port, limit=1<<15)
#     async with server:
#         await server.serve_forever()

# ---------- Main ----------
async def main():
    config_files = [
        ETC / "config-dev.yml",
        ETC / "config-qld.yml",
        ETC / "config-vic.yml",
        ETC / "config-wa.yml",
    ]

    # sanity check
    missing = [p for p in config_files if not p.exists()]
    if missing:
        print("Missing config files:", ", ".join(str(p) for p in missing))
        return

    tasks = [asyncio.create_task(start_server_for_cfg(p)) for p in config_files]
    await asyncio.gather(*tasks)

if __name__=="__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: pass

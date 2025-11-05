#!/usr/bin/env python3
import asyncio, os, pty, subprocess, sys, termios, tty, signal, ipaddress, shlex, json
from pathlib import Path

ETC = Path("/etc/cobol-proxy")
CFG = ETC / "config.yml"
SESS = ETC / "sessions.csv"  # "src_ip,allocated_pool_ip"

TMUX = "/usr/bin/tmux"

IAC=255; WILL=251; WONT=252; DO=253; DONT=254; SB=250; SE=240

def read_yaml(path:Path)->dict:
    if not path.exists(): return {}
    out={}
    for ln in path.read_text().splitlines():
        ln=ln.strip()
        if not ln or ln.startswith("#"): continue
        if ":" in ln:
            k,v=ln.split(":",1)
            out[k.strip()] = v.strip().strip('"\'')
    if "admin_ips" in out and str(out["admin_ips"]).startswith('['):
        try: out["admin_ips"] = json.loads(out["admin_ips"])
        except Exception: out["admin_ips"]=[]
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

async def run(*args, check=False):
    proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out,err = await proc.communicate()
    if check and proc.returncode!=0:
        raise RuntimeError(f"{args} -> {proc.returncode}: {err.decode()}")
    return out.decode(), err.decode(), proc.returncode

async def tmux_has(name:str)->bool:
    _,_,rc = await run(TMUX,"has-session","-t",name)
    return rc==0

async def ensure_tmux_for_ip(src_ip:str, env:dict):
    name = src_ip.replace(":", "_")
    if await tmux_has(name):
        return name
    env_export = " ".join(shlex.quote(f'{k}={v}') for k,v in env.items() if v)
    cmd = f"{env_export} /usr/local/bin/cobol-telnet.sh"
    await run(TMUX, "new-session", "-d", "-s", name, cmd, check=True)
    return name

async def tmux_detach_all(name:str):
    await run(TMUX, "detach", "-a", "-s", name)

def set_raw(fd): tty.setraw(fd, termios.TCSANOW)

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
            i+=1
        elif cmd==SB:
            while i<n-1 and not (buf[i]==IAC and buf[i+1]==SE):
                i+=1
            i+=2 if i<n-1 else 0
        else:
            pass
    return bytes(out)

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

def maybe_allocate_src_ip(src_ip:str, cfg:dict, sessions:dict)->str|None:
    bind = cfg.get("ip_bind","false")
    if str(bind).lower() in ("false","0","off"):
        return None
    pool = cfg.get("ip_pool_cidr","")
    iface = cfg.get("bind_iface","eth0")
    if not pool: return None

    if src_ip in sessions and sessions[src_ip]:
        return sessions[src_ip]

    taken=set(v for v in sessions.values() if v)
    ip = next_free_ip(pool, taken)
    if not ip: raise RuntimeError("IP pool exhausted")
    add_ip_alias(iface, pool, ip)
    sessions[src_ip]=ip
    save_sessions(sessions)
    return ip

async def bridge(reader:asyncio.StreamReader, writer:asyncio.StreamWriter, tmux_name:str, detach_first:bool):
    pid, master_fd = pty.fork()
    if pid==0:
        os.execl(TMUX, TMUX, "attach", "-t", tmux_name)
    set_raw(master_fd)
    loop=asyncio.get_running_loop()
    tmux_reader=asyncio.StreamReader()
    proto=asyncio.StreamReaderProtocol(tmux_reader)
    await loop.connect_read_pipe(lambda: proto, os.fdopen(master_fd,'rb',buffering=0))
    tmux_writer=os.fdopen(master_fd,'wb',buffering=0)

    if detach_first:
        await tmux_detach_all(tmux_name)

    async def c2s():
        try:
            while True:
                data = await reader.read(4096)
                if not data: break
                tmux_writer.write(telnet_strip_iac(data))
        finally:
            try: os.kill(pid, signal.SIGHUP)
            except ProcessLookupError: pass

    async def s2c():
        try:
            while True:
                out = await tmux_reader.read(4096)
                if not out: break
                writer.write(out); await writer.drain()
        finally:
            writer.close()

    await asyncio.gather(c2s(), s2c())

async def handle_client(reader, writer):
    src_ip = "0.0.0.0"
    try:
        peer = writer.get_extra_info("peername")
        src_ip = peer[0] if peer else "0.0.0.0"

        cfg = read_yaml(CFG)
        sessions = load_sessions()

        admin_ips = cfg.get("admin_ips", [])
        detach_first = src_ip in admin_ips

        src_bind = maybe_allocate_src_ip(src_ip, cfg, sessions)

        env = {
            "COBOL_HOST": cfg.get("cobol_host","10.0.0.25"),
            "COBOL_PORT": cfg.get("cobol_port","23"),
            "TERM_TYPE": cfg.get("term_type","vt100"),
            "SRC_IP": src_bind or ""
        }

        tmux_name = await ensure_tmux_for_ip(src_ip, env)
        await bridge(reader, writer, tmux_name, detach_first)

        # ===== NEW: cleanup after bridge ends =====
        # If COBOL closed, the launcher exited, tmux session should be gone.
        if not await tmux_has(tmux_name):
            # Optionally prune the record so next connect is a clean create.
            # Comment out the next 3 lines if you prefer to keep the mapping.
            if src_ip in sessions:
                # keep the allocated pool IP sticky; or blank to free it:
                # sessions[src_ip] = ""   # uncomment to free IP on next reuse
                save_sessions(sessions)

    except Exception:
        try:
            writer.write(b"\r\n[proxy error]\r\n"); await writer.drain()
        except Exception: pass
        writer.close()

async def main():
    cfg = read_yaml(CFG)
    host = cfg.get("listen_host","0.0.0.0")
    port = int(cfg.get("listen_port","2323"))
    server = await asyncio.start_server(handle_client, host, port, limit=1<<15)
    async with server:
        await server.serve_forever()

if __name__=="__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: pass


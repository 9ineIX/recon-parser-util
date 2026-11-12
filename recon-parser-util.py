#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Iterable, Iterator, Optional
from urllib.parse import urlsplit

try:
    from defusedxml.ElementTree import ParseError, fromstring as xml_fromstring
except ImportError:
    from xml.etree.ElementTree import ParseError, fromstring as xml_fromstring

__version__ = "2.0.0"

VALID_STATES = {"open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"}
VALID_PROTOCOLS = {"tcp", "udp", "sctp", "ip"}
FORMATS = ("nmap", "nmap-xml", "nmap-grep", "gobuster")

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})(?:\.[A-Za-z0-9_-]{1,63})*\.?$")

NMAP_REPORT_RE = re.compile(r"^Nmap scan report for (?P<name>\S+)(?: \((?P<ip>[^)]+)\))?(?P<down> \[host down\])?$")
NMAP_PORT_RE = re.compile(r"^(?P<port>\d+)/(?P<proto>\w+)\s+(?P<state>[\w|]+)(?:\s+(?P<service>\S+))?(?:\s+(?P<rest>.*))?$")
NMAP_UP_RE = re.compile(r"^Host is up(?: \((?P<latency>[\d.]+s) latency\))?")
NMAP_MAC_RE = re.compile(r"^MAC Address: (?P<mac>\S+)(?: \((?P<vendor>.*)\))?$")
NMAP_DONE_RE = re.compile(r"Nmap done\b.*?(?P<total>\d+) IP address(?:es)? \((?P<up>\d+) hosts? up\)")
NMAP_REASON_RE = re.compile(r"^\S+(?: ttl \d+)?(?:\s+|$)")
NMAP_SCRIPT_RE = re.compile(r"^\|_?\s?")

GNMAP_LINE_RE = re.compile(r"^Host: (?P<ip>\S+) \((?P<name>[^)]*)\)\t(?P<fields>.*)$")
GNMAP_PORT_RE = re.compile(r"(?:^|,\s*)(\d+)/([^/]*)/([^/]*)/([^/]*)/([^/]*)/([^/]*)/([^/]*)/")

GOB_BANNER_RE = re.compile(r"^\[\+\]\s+(?P<key>[A-Za-z][A-Za-z ]*?)\s*:\s+(?P<value>.+)$")
GOB_DIR_RE = re.compile(
    r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)"
    r"(?:\s+\[Size:\s*(?P<size>\d+)\])?(?:\s+\[-->\s*(?P<redirect>[^\]]+)\])?"
)
GOB_FOUND_RE = re.compile(r"^Found:\s+(?P<name>\S+)(?P<rest>.*)$")
GOB_FUZZ_RE = re.compile(r"^\[Status=(?P<status>\d+)\]\s+\[Length=(?P<size>\d+)\](?:\s+\[Word=[^\]]*\])?\s+(?P<url>\S+)")
GOB_ERROR_RE = re.compile(r"^(?:\[ERROR\]|Error:)\s*(?P<msg>.*)$")


@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: str = ""
    version: str = ""
    scripts: list[str] = field(default_factory=list)


@dataclass
class Host:
    address: str
    hostname: str = ""
    status: str = "up"
    latency: str = ""
    mac: str = ""
    os: str = ""
    service_info: str = ""
    ports: list[Port] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)

    def add_port(self, port: Port) -> Port:
        for existing in self.ports:
            if existing.number == port.number and existing.protocol == port.protocol:
                existing.state = port.state
                existing.service = port.service or existing.service
                existing.version = port.version or existing.version
                existing.scripts.extend(s for s in port.scripts if s not in existing.scripts)
                return existing
        self.ports.append(port)
        return port


@dataclass
class WebFinding:
    kind: str
    url: str
    status: Optional[int] = None
    size: Optional[int] = None
    redirect: str = ""
    target: str = ""
    addresses: list[str] = field(default_factory=list)
    host: str = ""


@dataclass
class Report:
    hosts: dict[str, Host] = field(default_factory=dict)
    web: list[WebFinding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duplicates: int = 0

    def host(self, address: str, hostname: str = "") -> Host:
        h = self.hosts.get(address)
        if h is None:
            h = self.hosts[address] = Host(address=address, hostname=hostname)
        elif hostname and not h.hostname:
            h.hostname = hostname
        return h

    def add_web(self, finding: WebFinding) -> None:
        for existing in self.web:
            if existing.kind == finding.kind and existing.url == finding.url:
                self.duplicates += 1
                return
        self.web.append(finding)

    def warn(self, source: str, lineno: Optional[int], message: str) -> None:
        location = f"{source}:{lineno}" if lineno else source
        self.warnings.append(f"{location}: {message}")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def clean_lines(text: str) -> Iterator[tuple[int, str]]:
    for lineno, raw in enumerate(text.splitlines(), 1):
        parts = [p for p in ANSI_RE.sub("", raw).split("\r") if p.strip()]
        yield lineno, parts[-1].rstrip() if parts else ""


def detect_formats(text: str) -> list[str]:
    head = text.lstrip()[:4096]
    if head.startswith("<?xml") or "<nmaprun" in head:
        return ["nmap-xml"]
    found = []
    if re.search(r"^Host: \S+ \(.*\)\t(?:Status|Ports):", text, re.M):
        found.append("nmap-grep")
    elif re.search(r"^(?:Nmap scan report for |Starting Nmap |# Nmap )", text, re.M):
        found.append("nmap")
    if re.search(r"\(Status: \d+\)|^Found: |^\[Status=\d+\]|^Gobuster v|^\[\+\] Mode\s*:", text, re.M):
        found.append("gobuster")
    return found


def join_url(base: str, path: str) -> str:
    if "://" in path or not base:
        return path
    return base.rstrip("/") + "/" + path.lstrip("/")


def host_sort_key(host: Host):
    try:
        ip = ipaddress.ip_address(host.address)
        return (0, ip.version, int(ip), "")
    except ValueError:
        return (1, 0, 0, host.address.lower())


def _nmap_host(report: Report, name: str, ip: Optional[str], source: str, lineno: int) -> Host:
    address, hostname = (ip, name) if ip else (name, "")
    if ip and not is_ip(ip):
        report.warn(source, lineno, f"invalid IP address {ip!r} for host {name!r}")
    elif not ip and not is_ip(address) and not HOSTNAME_RE.match(address):
        report.warn(source, lineno, f"suspicious host name {address!r}")
    return report.host(address, hostname)


def _nmap_port(match, has_reason: bool, report: Report, source: str, lineno: Optional[int]) -> Optional[Port]:
    number, proto, state = int(match["port"]), match["proto"].lower(), match["state"].lower()
    if not 0 <= number <= 65535:
        report.warn(source, lineno, f"port {number} is out of range 0-65535, skipped")
        return None
    if proto not in VALID_PROTOCOLS:
        report.warn(source, lineno, f"unknown protocol {proto!r}, skipped")
        return None
    if state not in VALID_STATES:
        report.warn(source, lineno, f"unknown port state {state!r}, skipped")
        return None
    rest = (match["rest"] or "").strip()
    if has_reason:
        rest = NMAP_REASON_RE.sub("", rest, count=1)
    return Port(number, proto, state, match["service"] or "", rest)


def parse_nmap_text(text: str, source: str, report: Report) -> None:
    host: Optional[Host] = None
    last_port: Optional[Port] = None
    has_reason = in_host_scripts = False
    reported_up = 0
    done = None

    for lineno, line in clean_lines(text):
        s = line.strip()
        if not s:
            continue

        m = NMAP_REPORT_RE.match(s)
        if m:
            host = _nmap_host(report, m["name"], m["ip"], source, lineno)
            if m["down"]:
                host.status = "down"
            else:
                reported_up += 1
            last_port, has_reason, in_host_scripts = None, False, False
            continue

        m = NMAP_DONE_RE.search(s)
        if m:
            done = (int(m["total"]), int(m["up"]))
            continue

        if s.startswith("Warning:"):
            report.warn(source, lineno, f"nmap: {s[len('Warning:'):].strip()}")
            continue

        if host is None:
            if NMAP_PORT_RE.match(s):
                report.warn(source, lineno, "port line before any 'Nmap scan report for' line, skipped")
            continue

        if s.startswith("PORT "):
            has_reason = "REASON" in s.split()
            continue
        if s == "Host script results:":
            in_host_scripts = True
            continue
        if s.startswith("|"):
            target = host.scripts if in_host_scripts or last_port is None else last_port.scripts
            target.append(NMAP_SCRIPT_RE.sub("", s, count=1))
            continue

        m = NMAP_PORT_RE.match(s)
        if m:
            port = _nmap_port(m, has_reason, report, source, lineno)
            last_port = host.add_port(port) if port else None
            in_host_scripts = False
            continue

        m = NMAP_UP_RE.match(s)
        if m:
            host.status = "up"
            host.latency = m["latency"] or host.latency
            continue
        m = NMAP_MAC_RE.match(s)
        if m:
            host.mac = m["mac"] + (f" ({m['vendor']})" if m["vendor"] else "")
            continue
        if s.startswith("OS details:"):
            host.os = s.split(":", 1)[1].strip()
        elif s.startswith(("Running:", "Running (JUST GUESSING):")) and not host.os:
            host.os = s.split(":", 1)[1].strip()
        elif s.startswith("Aggressive OS guesses:") and not host.os:
            host.os = s.split(":", 1)[1].split(", ")[0].strip()
        elif s.startswith("Service Info:"):
            host.service_info = s.split(":", 1)[1].strip()

    if done is None:
        report.warn(source, None, "no 'Nmap done' line - the scan may have been interrupted")
    elif done[1] != reported_up:
        report.warn(source, None, f"nmap reports {done[1]} host(s) up but {reported_up} were found - output may be truncated")


def parse_nmap_grep(text: str, source: str, report: Report) -> None:
    done = False
    for lineno, line in clean_lines(text):
        if line.startswith("# Nmap done"):
            done = True
            continue
        m = GNMAP_LINE_RE.match(line)
        if not m:
            continue
        host = _nmap_host(report, m["name"] or m["ip"], m["ip"] if m["name"] else None, source, lineno)
        for chunk in m["fields"].split("\t"):
            key, _, value = chunk.partition(": ")
            if key == "Status":
                host.status = value.strip().lower()
            elif key == "OS":
                host.os = value.strip()
            elif key == "Ports":
                entries = GNMAP_PORT_RE.findall(value)
                if not entries and value.strip():
                    report.warn(source, lineno, "could not parse 'Ports' field")
                for number, state, proto, _owner, service, _rpc, version in entries:
                    fake = {"port": number, "proto": proto, "state": state, "service": service,
                            "rest": version.replace("|", "/")}
                    port = _nmap_port(fake, False, report, source, lineno)
                    if port:
                        host.add_port(port)
    if not done:
        report.warn(source, None, "no '# Nmap done' line - the scan may have been interrupted")


def parse_nmap_xml(text: str, source: str, report: Report) -> None:
    try:
        root = xml_fromstring(text)
    except ParseError as exc:
        report.warn(source, None, f"invalid XML ({exc}) - the scan may have been interrupted")
        return
    if root.tag != "nmaprun":
        report.warn(source, None, f"unexpected XML root <{root.tag}>, expected <nmaprun>")
        return

    reported_up = 0
    for h in root.iter("host"):
        addrs = {a.get("addrtype"): a for a in h.findall("address")}
        addr_el = addrs.get("ipv4") if "ipv4" in addrs else addrs.get("ipv6")
        if addr_el is None:
            report.warn(source, None, "<host> without an IP address, skipped")
            continue
        names = [n.get("name", "") for n in h.findall("hostnames/hostname")]
        user_names = [n.get("name", "") for n in h.findall("hostnames/hostname[@type='user']")]
        hostname = (user_names or names or [""])[0]
        host = _nmap_host(report, hostname or addr_el.get("addr", ""), addr_el.get("addr") if hostname else None, source, None)

        status = h.find("status")
        host.status = status.get("state", "unknown") if status is not None else "unknown"
        reported_up += host.status == "up"
        if "mac" in addrs:
            vendor = addrs["mac"].get("vendor")
            host.mac = addrs["mac"].get("addr", "") + (f" ({vendor})" if vendor else "")
        osmatch = h.find("os/osmatch")
        if osmatch is not None:
            host.os = osmatch.get("name", "")
        times = h.find("times")
        if times is not None and times.get("srtt", "").isdigit():
            host.latency = f"{int(times.get('srtt')) / 1_000_000:.4f}s"
        host.scripts.extend(f"{s.get('id')}: {s.get('output', '').strip()}" for s in h.findall("hostscript/script"))

        for p in h.findall("ports/port"):
            state_el, svc = p.find("state"), p.find("service")
            service = version = ""
            if svc is not None:
                service = svc.get("name", "")
                if svc.get("tunnel") == "ssl":
                    service = f"ssl/{service}"
                extra = svc.get("extrainfo")
                version = " ".join(filter(None, [svc.get("product"), svc.get("version"), f"({extra})" if extra else ""]))
            fake = {"port": p.get("portid", "-1"), "proto": p.get("protocol", ""),
                    "state": state_el.get("state", "") if state_el is not None else "",
                    "service": service, "rest": version}
            port = _nmap_port(fake, False, report, source, None)
            if port:
                port.scripts = [f"{s.get('id')}: {s.get('output', '').strip()}" for s in p.findall("script")]
                host.add_port(port)

    stats = root.find("runstats/hosts")
    if root.find("runstats/finished") is None or stats is None:
        report.warn(source, None, "no <runstats> - the scan may have been interrupted")
    elif int(stats.get("up", reported_up)) != reported_up:
        report.warn(source, None, f"nmap reports {stats.get('up')} host(s) up but {reported_up} were found")


def parse_gobuster(text: str, source: str, report: Report, base_url: str = "") -> None:
    target, mode = base_url, ""
    errors = found = 0
    missing_target_warned = False

    for lineno, line in clean_lines(text):
        s = line.strip()
        if not s:
            continue

        m = GOB_BANNER_RE.match(s)
        if m:
            key, value = m["key"].lower(), m["value"].strip()
            if key in ("url", "domain") and not base_url:
                target = value
                if key == "url" and urlsplit(value).scheme not in ("http", "https"):
                    report.warn(source, lineno, f"target URL {value!r} has no http(s) scheme")
            elif key == "mode":
                mode = value.lower()
            continue

        m = GOB_ERROR_RE.match(s)
        if m:
            errors += 1
            continue

        finding = None
        m = GOB_DIR_RE.match(s)
        if m:
            finding = WebFinding(
                kind="vhost" if mode == "vhost" else "dir",
                url=m["path"], status=int(m["status"]),
                size=int(m["size"]) if m["size"] else None,
                redirect=(m["redirect"] or "").strip(),
            )
        elif GOB_FUZZ_RE.match(s):
            m = GOB_FUZZ_RE.match(s)
            finding = WebFinding(kind="fuzz", url=m["url"], status=int(m["status"]), size=int(m["size"]))
        else:
            m = GOB_FOUND_RE.match(s)
            if m:
                rest = m["rest"]
                status = re.search(r"Status:\s*(\d+)", rest)
                size = re.search(r"Size:\s*(\d+)", rest)
                ips = re.search(r"\[([0-9a-fA-F.:,\s]+)\]", rest)
                is_vhost = mode == "vhost" or status is not None
                finding = WebFinding(
                    kind="vhost" if is_vhost else "dns", url=m["name"],
                    status=int(status[1]) if status else None,
                    size=int(size[1]) if size else None,
                    addresses=[a.strip() for a in ips[1].split(",") if a.strip()] if ips and not is_vhost else [],
                )
        if finding is None:
            continue

        if finding.status is not None and not 100 <= finding.status <= 599:
            report.warn(source, lineno, f"invalid HTTP status {finding.status}, skipped")
            continue
        for addr in finding.addresses:
            if not is_ip(addr):
                report.warn(source, lineno, f"invalid IP address {addr!r} for {finding.url}")
        if finding.kind in ("dns", "vhost") and not HOSTNAME_RE.match(finding.url):
            report.warn(source, lineno, f"suspicious host name {finding.url!r}")

        if finding.kind == "dir":
            if "://" in finding.url:
                parts = urlsplit(finding.url)
                finding.target = f"{parts.scheme}://{parts.netloc}"
            else:
                finding.target = target
                finding.url = join_url(target, finding.url)
                if not target and not missing_target_warned:
                    report.warn(source, lineno, "gobuster target URL unknown (no banner) - use --base-url to attach results to a host")
                    missing_target_warned = True
        elif not finding.target:
            finding.target = target
        report.add_web(finding)
        found += 1

    if errors:
        report.warn(source, None, f"gobuster reported {errors} request error(s) - results may be incomplete")
    if not found:
        report.warn(source, None, "no gobuster results found")


PARSERS = {
    "nmap": parse_nmap_text,
    "nmap-xml": parse_nmap_xml,
    "nmap-grep": parse_nmap_grep,
}


def parse_input(text: str, source: str, report: Report, fmt: str = "auto", base_url: str = "") -> list[str]:
    formats = detect_formats(text) if fmt == "auto" else [fmt]
    if not formats:
        report.warn(source, None, "unrecognised input - not nmap or gobuster output (use --type to force)")
    for f in formats:
        if f == "gobuster":
            parse_gobuster(text, source, report, base_url)
        else:
            PARSERS[f](text, source, report)
    return formats


def attach_web(report: Report) -> None:
    index: dict[str, str] = {}
    for h in report.hosts.values():
        index[h.address.lower()] = h.address
        if h.hostname:
            index.setdefault(h.hostname.lower(), h.address)
    for w in report.web:
        if w.kind == "dns":
            candidates = w.addresses + [w.url]
        elif w.kind == "vhost":
            candidates = [urlsplit(w.target).hostname or w.target, w.url]
        else:
            candidates = [urlsplit(w.url).hostname or ""]
        for c in candidates:
            if c and c.lower() in index:
                w.host = index[c.lower()]
                break


def parse_state_filter(value: str) -> Optional[set[str]]:
    if value.strip().lower() == "all":
        return None
    states = {s.strip().lower() for s in value.split(",") if s.strip()}
    unknown = states - VALID_STATES
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown state(s): {', '.join(sorted(unknown))}")
    return states


def parse_status_filter(value: str) -> set[int]:
    codes: set[int] = set()
    for part in filter(None, (p.strip() for p in value.split(","))):
        if re.fullmatch(r"\d{3}", part):
            codes.add(int(part))
        elif re.fullmatch(r"\d{3}-\d{3}", part):
            lo, hi = map(int, part.split("-"))
            codes.update(range(lo, hi + 1))
        elif re.fullmatch(r"[1-5]xx", part, re.I):
            codes.update(range(int(part[0]) * 100, int(part[0]) * 100 + 100))
        else:
            raise argparse.ArgumentTypeError(f"invalid status code or range: {part!r}")
    return codes


@dataclass
class View:
    hosts: list[tuple[Host, list[Port], list[WebFinding]]]
    unassigned: list[WebFinding]


def build_view(report: Report, states: Optional[set[str]], statuses: Optional[set[int]]) -> View:
    def keep(w: WebFinding) -> bool:
        return statuses is None or w.status is None or w.status in statuses

    hosts = []
    for h in sorted(report.hosts.values(), key=host_sort_key):
        ports = sorted((p for p in h.ports if states is None or p.state in states), key=lambda p: (p.protocol, p.number))
        web = [w for w in report.web if w.host == h.address and keep(w)]
        hosts.append((h, ports, web))
    return View(hosts, [w for w in report.web if not w.host and keep(w)])


def web_urls(view: View) -> list[str]:
    urls: list[str] = []
    for host, ports, _ in view.hosts:
        name = host.hostname or host.address
        if ":" in name:
            name = f"[{name}]"
        for p in ports:
            if p.state != "open" or p.protocol != "tcp" or "http" not in p.service:
                continue
            https = "ssl" in p.service or "https" in p.service or p.number in (443, 8443)
            scheme, default = ("https", 443) if https else ("http", 80)
            url = f"{scheme}://{name}" + ("" if p.number == default else f":{p.number}")
            if url not in urls:
                urls.append(url)
    return urls


class Style:
    BOLD, DIM, RED, GREEN, YELLOW, CYAN = "1", "2", "31", "32", "33", "36"

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, *codes: str) -> str:
        if not self.enabled or not codes:
            return text
        return f"\x1b[{';'.join(codes)}m{text}\x1b[0m"


def state_color(state: str) -> tuple[str, ...]:
    if state == "open":
        return (Style.GREEN,)
    if "filtered" in state:
        return (Style.YELLOW,)
    return (Style.RED,)


def status_color(status: Optional[int]) -> tuple[str, ...]:
    if status is None:
        return ()
    if status < 300:
        return (Style.GREEN,)
    if status < 400:
        return (Style.CYAN,)
    if status in (401, 403):
        return (Style.YELLOW,)
    return (Style.RED,)


def format_table(headers: list[str], rows: list[list[str]], st: Style, colors=None, indent: str = "  ") -> list[str]:
    widths = [max(len(str(r[i])) for r in [headers] + rows) for i in range(len(headers))]

    def fmt(row, header=False):
        cells = []
        for i, value in enumerate(row):
            text = str(value) if i == len(row) - 1 else str(value).ljust(widths[i])
            codes = (Style.BOLD,) if header else (colors(i, row) if colors else ())
            cells.append(st(text, *codes))
        return indent + "  ".join(cells).rstrip()

    return [fmt(headers, header=True)] + [fmt(r) for r in rows]


def web_rows(findings: list[WebFinding]) -> list[list[str]]:
    rows = []
    for w in findings:
        url = w.url + (f"  -> {w.redirect}" if w.redirect else "")
        if w.addresses:
            url += f"  [{', '.join(w.addresses)}]"
        rows.append([w.kind, str(w.status) if w.status is not None else "-",
                     str(w.size) if w.size is not None else "-", url])
    return rows


def web_color(i: int, row: list[str]) -> tuple[str, ...]:
    return status_color(int(row[1])) if i == 1 and row[1].isdigit() else ()


def summary(report: Report, view: View) -> dict:
    return {
        "hosts": len(view.hosts),
        "hosts_up": sum(h.status == "up" for h, _, _ in view.hosts),
        "ports": sum(len(p) for _, p, _ in view.hosts),
        "open_ports": sum(1 for _, ports, _ in view.hosts for p in ports if p.state == "open"),
        "web_findings": sum(len(w) for _, _, w in view.hosts) + len(view.unassigned),
        "duplicates_removed": report.duplicates,
        "warnings": len(report.warnings),
    }


def render_table(report: Report, view: View, st: Style, show_scripts: bool, state_label: str) -> str:
    width = 72
    out: list[str] = []
    for host, ports, web in view.hosts:
        title = host.address + (f" ({host.hostname})" if host.hostname else "")
        status = st(host.status.upper(), Style.GREEN if host.status == "up" else Style.RED)
        out += ["", st("=" * width, Style.DIM), f"{st('TARGET', Style.BOLD)}  {st(title, Style.BOLD)}  [{status}]"]
        for label, value in (("Latency", host.latency), ("OS", host.os), ("MAC", host.mac),
                             ("Service Info", host.service_info)):
            if value:
                out.append(f"  {st(label + ':', Style.DIM)} {value}")
        out.append(st("-" * width, Style.DIM))

        if ports:
            rows = [[f"{p.number}/{p.protocol}", p.state, p.service or "-", p.version] for p in ports]
            lines = format_table(["PORT", "STATE", "SERVICE", "VERSION"], rows, st,
                                 lambda i, r: state_color(r[1]) if i == 1 else ())
            out.append(lines[0])
            for port, line in zip(ports, lines[1:]):
                out.append(line)
                if show_scripts:
                    out += [st(f"      | {s}", Style.DIM) for s in port.scripts]
        else:
            out.append(f"  No ports matching state filter ({state_label}).")
        if show_scripts and host.scripts:
            out += ["", st("  HOST SCRIPTS", Style.BOLD)] + [st(f"      | {s}", Style.DIM) for s in host.scripts]
        if web:
            out += ["", st("  WEB CONTENT (gobuster)", Style.BOLD)]
            out += format_table(["TYPE", "STATUS", "SIZE", "URL"], web_rows(web), st, web_color)

    groups: dict[str, list[WebFinding]] = {}
    for w in view.unassigned:
        groups.setdefault(w.target or "unknown target", []).append(w)
    for target, findings in groups.items():
        out += ["", st("=" * width, Style.DIM), f"{st('GOBUSTER', Style.BOLD)}  {st(target, Style.BOLD)}"]
        if report.hosts:
            out.append(st("  (no matching nmap host)", Style.DIM))
        out.append(st("-" * width, Style.DIM))
        out += format_table(["TYPE", "STATUS", "SIZE", "URL"], web_rows(findings), st, web_color)

    s = summary(report, view)
    out += ["", st("=" * width, Style.DIM),
            f"Summary: {s['hosts']} host(s), {s['hosts_up']} up, {s['open_ports']} open port(s), "
            f"{s['web_findings']} web finding(s), {s['warnings']} warning(s)"
            + (f", {s['duplicates_removed']} duplicate(s) removed" if s["duplicates_removed"] else "")]
    return "\n".join(out).lstrip("\n") + "\n"


def render_markdown(report: Report, view: View, show_scripts: bool) -> str:
    def esc(value) -> str:
        return str(value).replace("|", "\\|")

    def table(headers, rows):
        lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
        return lines + ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]

    out = ["# Scan results", ""]
    for host, ports, web in view.hosts:
        out.append(f"## {host.address}" + (f" ({host.hostname})" if host.hostname else "") + f" - {host.status}")
        out.append("")
        for label, value in (("OS", host.os), ("MAC", host.mac), ("Service Info", host.service_info)):
            if value:
                out.append(f"- **{label}:** {value}")
        if ports:
            out += [""] + table(["Port", "State", "Service", "Version"],
                                [[f"{p.number}/{p.protocol}", p.state, p.service, p.version] for p in ports])
            if show_scripts:
                for p in ports:
                    if p.scripts:
                        out += ["", f"<details><summary>Scripts {p.number}/{p.protocol}</summary>", "",
                                "```", *p.scripts, "```", "</details>"]
        if web:
            out += ["", "### Web content", ""] + table(["Type", "Status", "Size", "URL"], web_rows(web))
        out.append("")
    if view.unassigned:
        out += ["## Gobuster (no matching nmap host)", ""] + table(["Type", "Status", "Size", "URL"], web_rows(view.unassigned)) + [""]
    if report.warnings:
        out += ["## Warnings", ""] + [f"- {esc(w)}" for w in report.warnings] + [""]
    return "\n".join(out)


def render_json(report: Report, view: View) -> str:
    def web_dict(w: WebFinding) -> dict:
        d = asdict(w)
        d.pop("host")
        return d

    data = {
        "summary": summary(report, view),
        "hosts": [{**{k: v for k, v in asdict(h).items() if k != "ports"},
                   "ports": [asdict(p) for p in ports],
                   "web": [web_dict(w) for w in web]} for h, ports, web in view.hosts],
        "unassigned_web": [web_dict(w) for w in view.unassigned],
        "warnings": report.warnings,
    }
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def render_csv(view: View) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "host", "hostname", "port", "protocol", "state", "service", "version",
                     "url", "status", "size", "redirect"])
    for host, ports, web in view.hosts:
        for p in ports:
            writer.writerow(["port", host.address, host.hostname, p.number, p.protocol, p.state,
                             p.service, p.version, "", "", "", ""])
        for w in web:
            writer.writerow([w.kind, host.address, host.hostname, "", "", "", "", "",
                             w.url, w.status or "", w.size if w.size is not None else "", w.redirect])
    for w in view.unassigned:
        writer.writerow([w.kind, "", "", "", "", "", "", "", w.url, w.status or "",
                         w.size if w.size is not None else "", w.redirect])
    return buf.getvalue()


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon-parser-util",
        description="Validate and structure nmap and gobuster output.",
        epilog="examples:\n"
               "  nmap -sV 10.10.10.5 | ./recon-parser-util.py\n"
               "  ./recon-parser-util.py scan.xml gobuster.txt -f md -o report.md\n"
               "  ./recon-parser-util.py scan.gnmap -f urls | xargs -I{} gobuster dir -u {} -w words.txt",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("inputs", nargs="*", metavar="FILE", help="input files ('-' or nothing = stdin)")
    p.add_argument("-t", "--type", choices=("auto",) + FORMATS, default="auto",
                   help="input format (default: auto-detect per file)")
    p.add_argument("-f", "--format", choices=("table", "json", "csv", "md", "urls"), default="table",
                   help="output format (default: table)")
    p.add_argument("-o", "--output", metavar="FILE", help="write output to FILE instead of stdout")
    p.add_argument("--state", type=parse_state_filter, default={"open"}, metavar="STATES",
                   help="port states to show, comma-separated, or 'all' (default: open)")
    p.add_argument("--status", type=parse_status_filter, metavar="CODES",
                   help="gobuster status codes to show, e.g. 200,301-302,4xx (default: all)")
    p.add_argument("-u", "--base-url", default="", metavar="URL",
                   help="gobuster target URL, for output saved with -o (which has no banner)")
    p.add_argument("--scripts", action="store_true", help="show NSE script output")
    p.add_argument("--no-color", action="store_true", help="disable colours")
    p.add_argument("-q", "--quiet", action="store_true", help="do not print warnings to stderr")
    p.add_argument("--strict", action="store_true", help="exit with code 3 if any warning was raised")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def read_inputs(paths: list[str]) -> Iterable[tuple[str, str]]:
    for path in paths or ["-"]:
        if path == "-":
            yield "<stdin>", sys.stdin.read()
        else:
            with open(path, encoding="utf-8", errors="replace") as fh:
                yield path, fh.read()


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    if not args.inputs and sys.stdin.isatty():
        parser.print_help(sys.stderr)
        return 2
    if args.base_url and urlsplit(args.base_url).scheme not in ("http", "https"):
        parser.error("--base-url must start with http:// or https://")

    report = Report()
    try:
        for source, text in read_inputs(args.inputs):
            if not text.strip():
                report.warn(source, None, "input is empty")
                continue
            parse_input(text, source, report, args.type, args.base_url)
    except OSError as exc:
        print(f"recon-parser-util: error: {exc}", file=sys.stderr)
        return 2
    attach_web(report)

    if not report.hosts and not report.web:
        if not args.quiet:
            for w in report.warnings:
                print(f"warning: {w}", file=sys.stderr)
        print("recon-parser-util: no nmap or gobuster data found", file=sys.stderr)
        return 1

    view = build_view(report, args.state, args.status)
    st = Style(not args.no_color and not args.output and sys.stdout.isatty())
    state_label = "all" if args.state is None else ",".join(sorted(args.state))
    if args.format == "json":
        result = render_json(report, view)
    elif args.format == "csv":
        result = render_csv(view)
    elif args.format == "md":
        result = render_markdown(report, view, args.scripts)
    elif args.format == "urls":
        urls = web_urls(view)
        result = "\n".join(urls) + "\n" if urls else ""
    else:
        result = render_table(report, view, st, args.scripts, state_label)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(result)
    else:
        sys.stdout.write(result)

    if report.warnings and not args.quiet:
        warn = Style(not args.no_color and sys.stderr.isatty())
        for w in report.warnings:
            print(warn("warning: ", Style.YELLOW) + w, file=sys.stderr)

    if args.strict and report.warnings:
        return 3
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(0)

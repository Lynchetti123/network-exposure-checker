#!/usr/bin/env python3
"""
Local Network Exposure Checker  (COMP H2702 - Scenario D)

LOCAL-ONLY tool: checks 127.0.0.1 and the fixed ports from ports.txt,
collects safe banner / HTTP evidence and writes an analyst-style report
(console + TXT + CSV + JSON).

Security problem: before a system is exposed, an analyst needs to know
which TCP ports are listening, what is answering on them, and whether
that exposure is expected. An OPEN port is a fact, not a vulnerability.
"""

import argparse
import csv
import http.client
import ipaddress
import json
import os
import socket
import sys
from datetime import datetime

DEFAULT_TIMEOUT = 1.5          # seconds; short because everything is local
LOCAL_DEFAULT_TARGET = "127.0.0.1"


# --------------------------------------------------------------------------
# 1. Loading and validation
# --------------------------------------------------------------------------
def read_clean_lines(filename):
    """Return non-empty, non-comment lines of a text file.
    Raises FileNotFoundError / PermissionError to the caller."""
    lines = []
    with open(filename, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()   # drop comments
            if line:
                lines.append(line)
    return lines


def validate_target(target, approved_targets):
    """Return (ok, reason). Only loopback is allowed unless the user
    explicitly approved the address with --allow-target."""
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return False, "not a valid IP address"
    if ip.is_loopback:
        return True, "loopback address"
    if target in approved_targets:
        return True, "explicitly approved by user"
    return False, "non-local target rejected (local-only project)"


def load_targets(filename, approved_targets):
    """Read targets.txt and keep only valid, allowed, de-duplicated targets."""
    accepted, rejected = [], []
    try:
        lines = read_clean_lines(filename)
    except (FileNotFoundError, PermissionError) as err:
        print(f"[!] Cannot read targets file '{filename}': {err}")
        print(f"[i] Falling back to {LOCAL_DEFAULT_TARGET} (local-only default).")
        return [LOCAL_DEFAULT_TARGET], []
    for line in lines:
        ok, reason = validate_target(line, approved_targets)
        if ok and line not in accepted:
            accepted.append(line)
        elif not ok:
            rejected.append((line, reason))
    return accepted, rejected


def load_ports(filename):
    """Read ports.txt. Accepts one port per line (extra text after the
    port, e.g. '8080,http', is ignored). Returns (ports, invalid_entries)."""
    ports, invalid = [], []
    try:
        lines = read_clean_lines(filename)
    except (FileNotFoundError, PermissionError) as err:
        print(f"[!] Cannot read ports file '{filename}': {err}")
        return [], [("<file>", str(err))]
    for line in lines:
        token = line.replace(",", " ").split()[0]
        try:
            port = int(token)
        except ValueError:
            invalid.append((line, "not a number"))
            continue
        if not 1 <= port <= 65535:
            invalid.append((line, "outside 1-65535"))
        elif port not in ports:
            ports.append(port)
    return ports, invalid


# --------------------------------------------------------------------------
# 2. Network checks (TCP connect, banner, HTTP)
# --------------------------------------------------------------------------
def check_port(target, port, timeout):
    """TCP connect check. Returns ('OPEN'|'CLOSED', error_note)."""
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return "OPEN", ""
    except ConnectionRefusedError:
        return "CLOSED", "connection refused"
    except socket.timeout:
        return "CLOSED", "timed out"
    except OSError as err:
        return "CLOSED", f"os error: {err}"


def grab_banner(target, port, timeout):
    """Read a short banner the service sends on connect. If it stays silent,
    send a harmless CRLF once. Returns the banner text or ''."""
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(1024)
            except socket.timeout:
                data = b""
            if not data:
                try:
                    s.sendall(b"\r\n")
                    data = s.recv(1024)
                except (socket.timeout, OSError):
                    data = b""
            return data.decode("utf-8", errors="replace").strip()
    except OSError:
        return ""


def http_probe(target, port, timeout):
    """Normal HTTP GET / request. Returns a dict (status, content type,
    server header, body length) or None if the service is not HTTP."""
    conn = http.client.HTTPConnection(target, port, timeout=timeout)
    try:
        conn.request("GET", "/", headers={"User-Agent": "COMP-H2702-checker"})
        resp = conn.getresponse()
        body = resp.read(4096)
        return {
            "status": resp.status,
            "reason": resp.reason,
            "content_type": resp.getheader("Content-Type", "unknown"),
            "server": resp.getheader("Server", "unknown"),
            "body_preview": body.decode("utf-8", errors="replace")[:120].strip(),
        }
    except (http.client.HTTPException, OSError, ValueError):
        return None
    finally:
        conn.close()


# --------------------------------------------------------------------------
# 3. Analysis
# --------------------------------------------------------------------------
def interpret_exposure(result):
    """Short analyst-facing interpretation of one port result."""
    if result["state"] == "CLOSED":
        return "No listener: nothing to review on this port."
    if result["http"]:
        return ("Open HTTP service. Review whether a web service is expected "
                "here, what it serves and whether it needs authentication/TLS.")
    if result["banner"]:
        return ("Open service that identifies itself via banner. Banners can "
                "reveal software/version, so confirm the service is expected.")
    return ("Open port with no banner. A listener exists but its purpose is "
            "unclear: identify the owning process before judging risk.")


def analyse_target(target, ports, timeout):
    """Run all checks for one target; return list of result dicts."""
    results = []
    for port in ports:
        state, note = check_port(target, port, timeout)
        result = {"target": target, "port": port, "state": state,
                  "note": note, "banner": "", "http": None}
        if state == "OPEN":
            result["banner"] = grab_banner(target, port, timeout)
            if not result["banner"]:           # silent service: try HTTP
                result["http"] = http_probe(target, port, timeout)
        result["interpretation"] = interpret_exposure(result)
        results.append(result)
    return results


def summarise(results):
    """Counts of open and closed ports."""
    open_n = sum(1 for r in results if r["state"] == "OPEN")
    return {"total": len(results), "open": open_n,
            "closed": len(results) - open_n}


# --------------------------------------------------------------------------
# 4. Reporting
# --------------------------------------------------------------------------
def service_label(r):
    if r["http"]:
        return f"HTTP {r['http']['status']} ({r['http']['content_type']})"
    if r["banner"]:
        return "Banner: " + r["banner"].replace("\n", " ")[:60]
    return "-"


def build_text_report(results, summary, rejected_targets, invalid_ports):
    lines = ["=" * 64,
             "LOCAL NETWORK EXPOSURE REPORT",
             f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}",
             "Scope: localhost only, fixed supplied ports",
             "=" * 64, "",
             f"Ports checked: {summary['total']}   "
             f"OPEN: {summary['open']}   CLOSED: {summary['closed']}", ""]
    lines.append(f"{'PORT':<7}{'STATE':<8}EVIDENCE")
    lines.append("-" * 64)
    for r in results:
        lines.append(f"{r['port']:<7}{r['state']:<8}{service_label(r)}")
    lines += ["", "INTERPRETATION", "-" * 64]
    for r in results:
        if r["state"] == "OPEN":
            lines.append(f"Port {r['port']}: {r['interpretation']}")
    if rejected_targets or invalid_ports:
        lines += ["", "INPUT PROBLEMS (skipped)", "-" * 64]
        lines += [f"Target '{t}': {why}" for t, why in rejected_targets]
        lines += [f"Port entry '{p}': {why}" for p, why in invalid_ports]
    lines += ["", "NOTE: an OPEN port shows a listening service, not a "
              "vulnerability. Risk depends on what runs there and how it "
              "is configured."]
    return "\n".join(lines)


def save_reports(results, summary, text_report, output_dir):
    """Write TXT, CSV and JSON. Returns the list of files written."""
    os.makedirs(output_dir, exist_ok=True)
    written = []
    try:
        txt_path = os.path.join(output_dir, "exposure_report.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(text_report + "\n")
        written.append(txt_path)

        csv_path = os.path.join(output_dir, "exposure_report.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["target", "port", "state", "banner", "http_status",
                        "content_type", "interpretation"])
            for r in results:
                h = r["http"] or {}
                w.writerow([r["target"], r["port"], r["state"],
                            r["banner"].replace("\n", " "),
                            h.get("status", ""), h.get("content_type", ""),
                            r["interpretation"]])
        written.append(csv_path)

        json_path = os.path.join(output_dir, "exposure_report.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({"generated": datetime.now().isoformat(),
                       "summary": summary, "results": results}, f, indent=2)
        written.append(json_path)
    except OSError as err:
        print(f"[!] Could not write reports: {err}")
    return written


# --------------------------------------------------------------------------
# 5. Main
# --------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Local-only TCP exposure checker")
    p.add_argument("--targets", default="targets.txt")
    p.add_argument("--ports", default="ports.txt")
    p.add_argument("--output-dir", default="output")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--allow-target", action="append", default=[],
                   help="explicitly approve a non-loopback target "
                        "(outside project scope unless authorised)")
    return p.parse_args()


def main():
    args = parse_args()
    targets, rejected = load_targets(args.targets, set(args.allow_target))
    ports, invalid = load_ports(args.ports)

    if not targets or not ports:
        print("[!] Nothing to check (no valid targets or ports). Exiting.")
        sys.exit(1)

    all_results = []
    for target in targets:
        all_results.extend(analyse_target(target, ports, args.timeout))

    summary = summarise(all_results)
    report = build_text_report(all_results, summary, rejected, invalid)
    print(report)
    files = save_reports(all_results, summary, report, args.output_dir)
    if files:
        print("\nSaved: " + ", ".join(files))
    if summary["open"] == 0:
        print("\n[i] No open ports found. Is local_test_services.py running?")


if __name__ == "__main__":
    main()
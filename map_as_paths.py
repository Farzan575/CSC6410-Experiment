"""
CSC 6410: Traceroute IP-to-AS mapping
Student: Farzan Khan
Student ID: F00621515
"""

import ipaddress
import json
import re
import time
from pathlib import Path

import requests

STUDENT = "Farzan Khan"
STUDENT_ID = "F00621515"

BASE = Path(__file__).resolve().parent
TRACE_DIR = BASE / "results" / "traceroutes"
OUT_DIR = BASE / "results" / "as_analysis"
OUT_DIR.mkdir(parents=True, exist_ok=True)

API = "https://stat.ripe.net/data"
session = requests.Session()
cache = {}


def ripe_data(endpoint, resource):
    key = (endpoint, resource)
    if key in cache:
        return cache[key]

    response = session.get(
        f"{API}/{endpoint}/data.json",
        params={"resource": resource},
        timeout=25,
    )
    response.raise_for_status()
    payload = response.json()

    if payload.get("status") != "ok":
        raise RuntimeError(f"RIPEstat returned: {payload.get('status')}")

    data = payload.get("data", {})
    cache[key] = data
    time.sleep(0.15)
    return data


def public_ip(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def read_trace(path):
    target_ip = None
    hops = []

    for line in path.read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        target = re.search(r"traceroute to .*?\(([\d.]+)\)", line)
        if target:
            target_ip = target.group(1)

        hop = re.match(
            r"^\s*(\d+)\s+(\d{1,3}(?:\.\d{1,3}){3})\s",
            line,
        )
        if hop:
            hops.append({
                "hop": int(hop.group(1)),
                "ip": hop.group(2),
            })

    return target_ip, hops


def get_asn(ip):
    data = ripe_data("network-info", ip)
    values = data.get("asns", [])
    return str(values[0]) if values else None


def get_as_name(asn):
    if not asn:
        return "Unknown"
    data = ripe_data("as-overview", f"AS{asn}")
    return data.get("holder", "Name unavailable")


def get_bgp_paths(target_ip):
    if not target_ip:
        return []

    data = ripe_data("bgp-state", target_ip)
    paths = []

    for route in data.get("bgp_state", []):
        path = route.get("path", [])
        if path:
            paths.append({
                "source_id": route.get("source_id", "Unknown"),
                "target_prefix": route.get("target_prefix", "Unknown"),
                "path": [str(asn) for asn in path]
            })

    return paths


def collapse_asns(asns):
    result = []
    for asn in asns:
        if asn and (not result or result[-1] != asn):
            result.append(asn)
    return result


def main():
    if not TRACE_DIR.is_dir():
        raise SystemExit(f"Traceroute directory missing: {TRACE_DIR}")

    files = sorted(TRACE_DIR.glob("*_*.txt"))
    if not files:
        raise SystemExit(f"No first-measurement files found in {TRACE_DIR}")

    report = []

    print(f"Student: {STUDENT} ({STUDENT_ID})")
    print(f"Traceroute folder: {TRACE_DIR}")

    for file in files:
        print(f"\n--- {file.name} ---")
        target_ip, hops = read_trace(file)
        mapped = []
        observed_asns = []

        for hop in hops:
            ip = hop["ip"]

            if not public_ip(ip):
                print(f"Hop {hop['hop']}: {ip} [private/non-global, skipped]")
                mapped.append({**hop, "asn": None, "as_name": None})
                continue

            try:
                asn = get_asn(ip)
                name = get_as_name(asn) if asn else "ASN unavailable"
                print(f"Hop {hop['hop']}: {ip} -> AS{asn or '?'} ({name})")
            except Exception as error:
                print(f"Hop {hop['hop']}: {ip} -> lookup failed: {error}")
                asn, name = None, "Lookup failed"

            mapped.append({**hop, "asn": asn, "as_name": name})
            if asn:
                observed_asns.append(asn)

        observed_path = collapse_asns(observed_asns)
        bgp_paths = []

        try:
            bgp_paths = get_bgp_paths(target_ip)
        except Exception as error:
            print(f"BGP lookup failed for {target_ip}: {error}")

        # RIPEstat paths are stored with source and prefix metadata.
        bgp_origins = sorted({
            route["path"][-1]
            for route in bgp_paths
            if route.get("path")
        })

        destination_reached = (
            target_ip is not None
            and any(hop["ip"] == target_ip for hop in hops)
        )

        origin_match = (
            observed_path[-1] in bgp_origins
            if destination_reached and observed_path and bgp_origins
            else None
        )

        bgp_asns = {
            asn
            for route in bgp_paths
            for asn in route.get("path", [])
        }

        print("Observed AS path:",
              " -> ".join("AS" + x for x in observed_path) or "Unavailable")
        print(f"RIPEstat BGP paths returned: {len(bgp_paths)}")
        print(f"BGP origin ASNs: {bgp_origins}")
        print(f"Observed final ASN matches a BGP origin: {origin_match}")

        report.append({
            "student": STUDENT,
            "student_id": STUDENT_ID,
            "file": file.name,
            "target_ip": target_ip,
            "responding_hops": mapped,
            "observed_as_path": observed_path,
            "bgp_paths": bgp_paths,
            "bgp_origin_asns": bgp_origins,
            "observed_final_as_matches_bgp_origin": origin_match,
            "observed_asns_present_in_bgp_paths": {
                asn: asn in bgp_asns for asn in observed_path
            },
        })

    output = OUT_DIR / "as_path_analysis.json"
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nAnalysis saved to: {output}")


if __name__ == "__main__":
    main()




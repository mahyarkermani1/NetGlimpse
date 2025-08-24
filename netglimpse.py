#!/usr/bin/env python3
"""
NetGlimpse - quick Shodan InternetDB inspector
==============================================

Short description:
    NetGlimpse provides quick inspection of single IPs and CIDR ranges
    via Shodan's InternetDB. Outputs include colored ASCII banner + tables
    (for human reading) and machine-friendly modes for scripting.

Contacts:
    Website:  mahyar.sbs
    Email:    mahyar@mahyar.sbs

Quick examples:
    # single IP
    python3 netglimpse.py -ic 8.8.8.8

    # mixed IPs and CIDRs on one line (unquoted)
    python3 netglimpse.py -ic 8.8.8.8,1.1.1.0/30,9.9.9.9

    # mixed IPs and CIDRs on one line (with spaces, unquoted)
    python3 netglimpse.py -ic 103.4.197.120/29, 208.68.244.0/22

    # mixed tokens (space separated, comma spacing variations)
    python3 netglimpse.py -ic 103.4.197.120/29, 208.68.244.0/22 1.2.3.4

Note:
    Large CIDRs may expand to many hosts; consider sampling or using
    a small delay via --delay to respect remote service limits.
"""

import argparse
import ipaddress
import sys
import requests
import time
import random
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional

from fake_useragent import UserAgent
from rich.console import Console
from rich.table import Table
from rich.text import Text
import pyfiglet

# --- Project Constants ---
PROJECT_NAME = "NetGlimpse"
VERSION = "1.2.0"

# --- Setup ---
console = Console()                    # rich console for colored output
try:
    ua = UserAgent()                   # fake user-agent generator
except Exception:
    ua = None                          # fallback used if fake_useragent fails initialization


# ---------- UI Helpers ----------

def _rand_color() -> str:
    colors = ["red", "green", "yellow", "blue", "magenta", "cyan"]
    return random.choice(colors)

def print_separator(char: str = "─") -> None:
    """
    Print a horizontal separator line across terminal width.
    Uses a simple character to remain portable across terminals.
    """
    width = shutil.get_terminal_size((80, 24)).columns
    console.print(char * width)

def generate_banner() -> None:
    """
    Produce an ASCII banner using pyfiglet and display contact line.
    Styles applied via Console 'style' parameter to avoid markup tag mismatches.
    """
    color = _rand_color()
    banner_text = pyfiglet.figlet_format(PROJECT_NAME, font="slant")
    console.print(Text(banner_text, style=f"bold {color}"))
    contact = f"> Website: mahyar.sbs | Email: mahyar@mahyar.sbs | Version: {VERSION}"
    console.print(Text(contact, style=f"bold {color}"))
    print_separator()


# ---------- Shodan InternetDB ----------

def _headers() -> Dict[str, str]:
    """
    Build request headers, with randomized User-Agent if available.
    """
    agent = None
    if ua:
        try:
            agent = ua.random
        except Exception:
            agent = None
    if not agent:
        agent = "Mozilla/5.0 (compatible; NetGlimpse/1.0; +https://mahyar.sbs)"
    return {"User-Agent": agent}

def get_ip_data(ip: str, delay: float) -> Tuple[str, Optional[Dict]]:
    """
    Fetch JSON data for a single IP from Shodan InternetDB.
    Returns (ip, data) where data is None if not found or on any failure.
    Optional delay applied before the request for gentle pacing with threading.
    """
    if delay > 0:
        time.sleep(delay)
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        r = requests.get(url, headers=_headers(), timeout=15)
        if r.status_code != 200:
            return ip, None
        data = r.json()
        # Treat as "not found" when no meaningful fields present (e.g., empty ports)
        if not data or ("ports" in data and not data["ports"]):
            return ip, None
        return ip, data
    except requests.RequestException:
        return ip, None


# ---------- Rendering ----------

def print_ip_table(ip: str, data: Dict) -> None:
    """
    Print a rich table containing IP details returned by InternetDB.
    Fields included: hostnames, ports, tags, vulns, cpes.
    """
    table = Table(title=f"Shodan InternetDB Info for {ip}")
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="magenta")

    table.add_row("IP", ip)
    table.add_row("Hostnames", ", ".join(data.get("hostnames", []) or ["N/A"]))
    table.add_row("Ports", ", ".join(map(str, data.get("ports", [])) or ["N/A"]))
    table.add_row("Tags", ", ".join(data.get("tags", []) or ["N/A"]))
    table.add_row("Vulns", ", ".join(map(str, data.get("vulns", []) or ["N/A"])))
    table.add_row("CPES", ", ".join(data.get("cpes", []) or ["N/A"]))

    console.print(table)
    print_separator()


# ---------- Target Parsing ----------

def parse_targets_from_list(raw_tokens: List[str]) -> List[str]:
    """
    Normalize a list of input tokens into a flat list of IP/CIDR strings.
    Each token may contain commas and arbitrary spaces, so split on commas
    and trim whitespace. Empty items are ignored.

    Example handled forms:
      - ['103.4.197.120/29,', '208.68.244.0/22']
      - ['103.4.197.120/29,208.68.244.0/22']
      - ['103.4.197.120/29,', '208.68.244.0/22', '1.2.3.4']
      - ['103.4.197.120/29, 208.68.244.0/22']
    """
    targets: List[str] = []
    for tok in raw_tokens:
        parts = tok.split(',')
        for p in parts:
            item = p.strip()
            if item:
                targets.append(item)
    return targets

def expand_targets_to_ips(targets: List[str]) -> List[str]:
    """
    Expand given list of IP/CIDR strings into individual IP strings.
    Invalid targets are skipped and reported via console message.
    """
    ips_to_check: List[str] = []
    for target in targets:
        try:
            network = ipaddress.ip_network(target, strict=False)
            if network.num_addresses == 1:
                ips_to_check.append(str(network.network_address))
            else:
                for ip in network.hosts():
                    ips_to_check.append(str(ip))
        except ValueError:
            console.print(f"[bold red][!] Invalid IP/CIDR format: {target}[/bold red]")
            continue
    return ips_to_check


# ---------- Main ----------

def main() -> None:
    """
    Parse arguments, perform queries (threaded), and present results based on selected mode.
    Modes supported:
      - default: banner + tables for found, grouped list for not-found at end; also logs per-result in real time
      - --silent-all (-sa): only print found IPs, one per line (no banners/tables)
      - --silent-not-found (-snf): show banner + tables for found; suppress not-found items completely
      - --silent-found (-sf): show banner + grouped list of not-found IPs; suppress found tables

    Combination rules:
      - All three switches together -> error.
      - -sa and -snf -> equivalent to -sa (found IPs only, no banner/logs).
      - -sa and -sf  -> output only not-found IPs, one per line, no banner/logs.
    """
    parser = argparse.ArgumentParser(
        description="Check IPs/CIDRs against Shodan InternetDB with flexible input, threading, and output.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "-ic", "--ip-cidr",
        required=True,
        nargs='+',
        help=(
            "One or more targets. Each token may be a single IP, a CIDR, or a comma-separated\n"
            "list of IPs/CIDRs. Quoted or unquoted forms accepted. Examples:\n"
            "  -ic 8.8.8.8 1.1.1.0/30\n"
            "  -ic \"103.4.197.120/29, 208.68.244.0/22\"\n"
            "  -ic 103.4.197.120/29, 208.68.244.0/22"
        )
    )

    # Output modes (mutually exclusive for argparse itself)
    parser.add_argument(
        "-sa", "--silent-all",
        action="store_true",
        help="Silent All: Output only IPs found in Shodan, one per line. No banners, tables, or colors."
    )
    parser.add_argument(
        "-snf", "--silent-not-found",
        action="store_true",
        help="Silent Not Found: Suppress output for IPs not found. Show banner and tables for found IPs."
    )
    parser.add_argument(
        "-sf", "--silent-found",
        action="store_true",
        help="Silent Found: Suppress output for IPs found. Show banner and grouped list of IPs NOT found."
    )

    parser.add_argument(
        "-d", "--delay",
        type=float,
        default=0.0,
        help="Delay (seconds) before each request (applied per thread). Default: 0.0"
    )
    parser.add_argument(
        "-t", "--thread",
        type=int,
        default=5,
        help="Number of threads for parallel queries. Default: 5, Max: 50"
    )

    args = parser.parse_args()

    # Validate thread count
    threads = min(max(args.thread, 1), 50)

    # Validate forbidden combination: all three cannot be used together
    if args.silent_all and args.silent_not_found and args.silent_found:
        console.print("[bold red][!] -sa, -snf and -sf cannot be used together.[/bold red]")
        sys.exit(2)

    # Determine effective mode according to rules
    if args.silent_all and args.silent_not_found:
        effective_mode = "silent_all"               # as specified: equals -sa
    elif args.silent_all and args.silent_found:
        effective_mode = "silent_notfound_only"     # print not-found IPs only, no banner/logs
    elif args.silent_all:
        effective_mode = "silent_all"
    elif args.silent_not_found:
        effective_mode = "silent_notfound"
    elif args.silent_found:
        effective_mode = "silent_found"
    else:
        effective_mode = "default"

    # Normalize tokens (support spaces around commas and multiple tokens)
    normalized_targets = parse_targets_from_list(args.ip_cidr)

    # Expand normalized targets into individual IPs
    ips_to_check = expand_targets_to_ips(normalized_targets)
    if not ips_to_check:
        console.print("[bold red][!] No valid IPs to process. Exiting.[/bold red]")
        sys.exit(1)

    # Banner (printed unless pure-no-banner modes)
    if effective_mode not in ("silent_all", "silent_notfound_only"):
        generate_banner()

    found_ips_data: Dict[str, Dict] = {}
    not_found_ips: List[str] = []

    # Threaded querying with real-time logging when not silent
    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(get_ip_data, ip, args.delay): ip for ip in ips_to_check}
            for future in as_completed(futures):
                ip, data = future.result()

                # Accumulate
                if data:
                    found_ips_data[ip] = data
                else:
                    not_found_ips.append(ip)

                # Real-time outputs per mode
                if effective_mode == "silent_all":
                    if data:
                        print(ip)
                elif effective_mode == "silent_notfound":
                    if data:
                        print_ip_table(ip, data)
                elif effective_mode == "silent_found":
                    # Defer printing: grouped list at end
                    pass
                elif effective_mode == "silent_notfound_only":
                    if not data:
                        print(ip)
                else:  # default
                    if data:
                        print_ip_table(ip, data)
                    else:
                        console.print(f"[yellow]{ip} not found in Shodan InternetDB[/yellow]")
                        print_separator()

    except KeyboardInterrupt:
        console.print("\n[bold red][!] Interrupted. Exiting.[/bold red]")
        sys.exit(0)

    # Final grouped outputs (where relevant)
    if effective_mode == "silent_found":
        if not_found_ips:
            console.print("\n[bold red]--- IPs Not Found ---[/bold red]")
            for ip in not_found_ips:
                print(f"- {ip}")
        else:
            console.print("\n[bold green]All targets were found in Shodan InternetDB.[/bold green]")
    elif effective_mode == "silent_notfound":
        if not found_ips_data:
            console.print("\n[bold yellow]No IPs were found in Shodan InternetDB.[/bold yellow]")
    elif effective_mode == "default":
        if not_found_ips:
            console.print("\n[bold yellow]--- IPs Not Found ---[/bold yellow]")
            for ip in not_found_ips:
                console.print(f"- {ip}")

if __name__ == "__main__":
    main()

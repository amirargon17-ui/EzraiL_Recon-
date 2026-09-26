#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import time
import socket
import random
import subprocess
import select
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings()

try:
    import colorama
    colorama.init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

R = "\033[91m" if HAS_COLOR else ""
G = "\033[92m" if HAS_COLOR else ""
Y = "\033[93m" if HAS_COLOR else ""
C = "\033[96m" if HAS_COLOR else ""
O = "\033[38;5;208m" if HAS_COLOR else ""
BOLD = "\033[1m" if HAS_COLOR else ""
RS = "\033[0m" if HAS_COLOR else ""


def clear():
    os.system("cls" if os.name == "nt" else "clear")


UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Linux; Android 14)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
]

BANNER = O + BOLD + """
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
""" + RS + O + BOLD + "              EZRAIL RECON" + RS


def box(title, rows):
    w = 44
    print(C + "+" + "-" * w + "+" + RS)
    print(C + "|" + RS + title.center(w) + C + "|" + RS)
    print(C + "+" + "-" * w + "+" + RS)
    for k, v in rows:
        line = "  " + str(k).ljust(14) + "| " + str(v)
        print(C + "|" + RS + G + line[:w].ljust(w) + C + "|" + RS)
    print(C + "+" + "-" * w + "+" + RS)


def back(s=15):
    print("\n" + Y + "Enter=menu (auto " + str(s) + "s)" + RS)
    try:
        r, _, _ = select.select([sys.stdin], [], [], s)
        if r:
            sys.stdin.readline()
    except:
        time.sleep(s)


def clean_domain(t):
    return t.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0].strip()


# ========== 1. WHOIS Lookup ==========

def whois_lookup():
    print("\n" + C + "--- WHOIS Lookup ---" + RS)
    t = input(C + "Domain: " + RS).strip()
    if not t:
        return

    t = clean_domain(t)
    print(Y + "\nQuerying WHOIS for " + t + " ..." + RS)

    try:
        r = requests.get("https://api.whois.vu/?q=" + t, timeout=10).json()
        if r and r.get("domain"):
            rows = []
            for k, v in r.items():
                if v and str(v) != "None" and k != "rawdata":
                    rows.append((str(k)[:14], str(v)[:28]))
            if rows:
                box("WHOIS - " + t, rows)
                return
    except:
        pass

    try:
        result = subprocess.run(["whois", t], capture_output=True, text=True, timeout=15, shell=True)
        if result.stdout and "No match" not in result.stdout:
            lines = result.stdout.split("\n")
            important = []
            for line in lines:
                if any(k in line.lower() for k in ["registrar", "creation", "expir", "updated", "name server", "status", "registrant"]):
                    important.append(line.strip())
            if important:
                print(G + "\n" + "\n".join(important[:20]) + RS)
                return
    except:
        pass

    try:
        r = requests.get("https://rdap.org/domain/" + t, timeout=10).json()
        rows = [
            ("Domain", r.get("ldhName", t)),
            ("Status", ",".join(r.get("status", []))[:28]),
        ]
        for ev in r.get("events", [])[:4]:
            rows.append((str(ev.get("eventAction", "event"))[:14], str(ev.get("eventDate", ""))[:28]))
        for ns in r.get("nameservers", [])[:3]:
            rows.append(("Nameserver", ns.get("ldhName", "")[:28]))
        box("WHOIS - " + t, rows)
    except Exception as e:
        print(R + "Failed: " + str(e) + RS)
        print(Y + "Tip: pkg install whois" + RS)


# ========== 2. DNS Enumeration ==========

def dns_enum():
    print("\n" + C + "--- DNS Enumeration ---" + RS)
    t = input(C + "Domain: " + RS).strip()
    if not t:
        return

    t = clean_domain(t)
    print(Y + "\nEnumerating DNS for " + t + " ...\n" + RS)

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    for rt in record_types:
        try:
            result = subprocess.run(
                ["nslookup", "-type=" + rt, t],
                capture_output=True, text=True, timeout=10, shell=True
            )
            output = result.stdout.strip()
            if output and "NXDOMAIN" not in output and "can't find" not in output.lower():
                lines = output.split("\n")
                clean_lines = []
                for l in lines:
                    if "Address" in l or "exchanger" in l or "nameserver" in l or "text" in l.lower() or "canonical" in l.lower() or "origin" in l.lower():
                        clean_lines.append(l.strip())
                if clean_lines:
                    print(C + "[" + rt + "]" + RS)
                    for cl in clean_lines[:5]:
                        print(G + "  " + cl + RS)
                    print()
        except:
            pass

    print(Y + "\nChecking common subdomains...\n" + RS)
    subs = ["www", "mail", "ftp", "admin", "api", "dev", "test", "blog",
            "shop", "ns1", "ns2", "cdn", "portal", "vpn", "cpanel",
            "webmail", "smtp", "pop", "imap", "mysql"]

    found = []

    def check_sub(s):
        try:
            ip = socket.gethostbyname(s + "." + t)
            return (s + "." + t, ip)
        except:
            return None

    with ThreadPoolExecutor(max_workers=10) as ex:
        results = ex.map(check_sub, subs)
        for r in results:
            if r:
                found.append(r)
                print(G + "  [+] " + r[0] + " -> " + r[1] + RS)

    if found:
        print()
        box("SUBDOMAINS FOUND", [(n[:14], i[:28]) for n, i in found[:10]])
    else:
        print(R + "No common subdomains found." + RS)


# ========== 3. Social Media Scraper ==========

def social_scraper():
    print("\n" + C + "--- Social Media Scraper ---" + RS)
    u = input(C + "Username: " + RS).strip()
    if not u:
        return

    u = u.lstrip("@")
    print(Y + "\nSearching '" + u + "' on platforms...\n" + RS)

    platforms = [
        ("Instagram", "https://www.instagram.com/" + u + "/"),
        ("Twitter/X", "https://twitter.com/" + u),
        ("GitHub", "https://github.com/" + u),
        ("Reddit", "https://www.reddit.com/user/" + u),
        ("TikTok", "https://www.tiktok.com/@" + u),
        ("YouTube", "https://www.youtube.com/@" + u),
        ("Telegram", "https://t.me/" + u),
        ("Pinterest", "https://www.pinterest.com/" + u + "/"),
        ("Medium", "https://medium.com/@" + u),
        ("Twitch", "https://www.twitch.tv/" + u),
        ("SoundCloud", "https://soundcloud.com/" + u),
        ("Steam", "https://steamcommunity.com/id/" + u),
        ("Facebook", "https://www.facebook.com/" + u),
        ("LinkedIn", "https://www.linkedin.com/in/" + u),
        ("Snapchat", "https://www.snapchat.com/add/" + u),
        ("GitLab", "https://gitlab.com/" + u),
        ("Dev.to", "https://dev.to/" + u),
        ("Keybase", "https://keybase.io/" + u),
        ("About.me", "https://about.me/" + u),
        ("Behance", "https://www.behance.net/" + u),
    ]

    headers = {"User-Agent": random.choice(UAS)}
    found = []

    def check(item):
        name, url = item
        try:
            r = requests.get(url, headers=headers, timeout=8, verify=False, allow_redirects=True)
            if r.status_code == 200:
                return (name, "FOUND", url[:30])
            elif r.status_code in [301, 302, 303]:
                return (name, "REDIRECT", url[:30])
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as ex:
        results = ex.map(check, platforms)
        for r in results:
            if r:
                found.append(r)
                color = G if r[1] == "FOUND" else Y
                print(color + "  [+]" + RS + " " + r[0].ljust(14) + " -> " + r[1] + RS)

    if found:
        print()
        box("FOUND ON " + str(len(found)) + " PLATFORMS",
            [(n[:14], s) for n, s, _ in found[:12]])
    else:
        print(R + "\nNo accounts found." + RS)


# ========== Menu ==========

def show():
    clear()
    print(BANNER)
    print(C + "  " + time.strftime("%H:%M:%S") + "  |  " + time.strftime("%Y/%m/%d") + RS)
    print()
    print(O + "  -- RECON TOOLS --" + RS)
    print(Y + "  [1]" + RS + " WHOIS Lookup")
    print(Y + "  [2]" + RS + " DNS Enumeration")
    print(Y + "  [3]" + RS + " Social Media Scraper")
    print()
    print(Y + "  [0]" + RS + " Exit")


def menu():
    while True:
        show()
        c = input("\n" + C + "Select [0-3]: " + RS).strip()

        if c == "0":
            print(R + "\nBye." + RS)
            sys.exit(0)
        elif c == "1":
            whois_lookup()
        elif c == "2":
            dns_enum()
        elif c == "3":
            social_scraper()
        else:
            print(R + "Invalid" + RS)
            time.sleep(1)
            continue
        back()


if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print(R + "\nBye." + RS)
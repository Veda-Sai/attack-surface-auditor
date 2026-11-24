import asyncio
import html
import json
import re
import socket
from urllib.parse import urlparse
import aiohttp

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AttackSurfaceMapper/1.0"
}


def normalize_domain(raw: str) -> str:
    value = raw.strip().lower()
    if "://" in value:
        value = urlparse(value).netloc or value
    value = value.split("/")[0].lstrip("*.")
    return value.rstrip(".")


async def fetch_crt_subdomains(session, domain):
    """Query public Certificate Transparency logs (crt.sh) for subdomains."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    print(f"[*] Querying Certificate Transparency logs for *.{domain} ...")
    try:
        async with session.get(url, headers=HEADERS, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                print(f"[!] crt.sh returned status {resp.status}. Try again in a few seconds.")
                return []
            data = await resp.json(content_type=None)
            if not isinstance(data, list):
                return []

            subdomains = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for line in name_value.splitlines():
                    clean = line.strip().lower().lstrip("*.")
                    if clean == domain or clean.endswith(f".{domain}"):
                        subdomains.add(clean)
            return sorted(subdomains)
    except Exception as e:
        print(f"[!] Error querying crt.sh: {type(e).__name__}")
        return []


def resolve_ip(hostname):
    """Resolve hostname to an IPv4 address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


async def probe_host(session, semaphore, subdomain):
    """Check DNS resolution and probe HTTP/HTTPS for live web services."""
    async with semaphore:
        loop = asyncio.get_running_loop()
        ip = await loop.run_in_executor(None, resolve_ip, subdomain)
        if not ip:
            return None

        result = {
            "subdomain": subdomain,
            "ip": ip,
            "live_url": None,
            "status_code": None,
            "server": "Unknown",
            "title": "No Title",
        }

        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                async with session.get(
                    url,
                    headers=HEADERS,
                    timeout=aiohttp.ClientTimeout(total=12),
                    ssl=False,
                    allow_redirects=True,
                ) as resp:
                    body = await resp.text(errors="ignore")
                    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        raw_title = re.sub(r"\s+", " ", html.unescape(title_match.group(1))).strip()
                        title = raw_title[:70] if raw_title else "No Title"
                    else:
                        title = "No Title"

                    result["live_url"] = str(resp.url)
                    result["status_code"] = resp.status
                    result["server"] = resp.headers.get("Server", "Hidden")
                    result["title"] = title
                    return result
            except Exception:
                continue

        return result


async def run_mapper(raw_domain):
    domain = normalize_domain(raw_domain)
    if not domain:
        print("[-] Invalid domain.")
        return

    connector = aiohttp.TCPConnector(limit=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        subdomains = await fetch_crt_subdomains(session, domain)
        if not subdomains:
            print("[-] No subdomains found or crt.sh is temporarily busy.")
            return

        print(f"[+] Discovered {len(subdomains)} unique subdomains. Probing live hosts...\n")

        semaphore = asyncio.Semaphore(10)
        tasks = [probe_host(session, semaphore, sub) for sub in subdomains[:60]]
        raw_results = await asyncio.gather(*tasks)

        active_hosts = [r for r in raw_results if r is not None]

        for host in active_hosts:
            if host["live_url"]:
                print(
                    f"[LIVE] {host['subdomain']} ({host['ip']}) | "
                    f"HTTP {host['status_code']} | Server: {host['server']} | Title: {host['title']}"
                )
            else:
                print(f"[DNS ] {host['subdomain']} ({host['ip']}) | No HTTP/HTTPS response")

        filename = f"{domain.replace('.', '_')}_surface.json"
        output = {
            "domain": domain,
            "total_discovered": len(subdomains),
            "probed_count": min(len(subdomains), 60),
            "active_hosts": active_hosts,
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=4)

        print(f"\n[*] Scan complete: {len(active_hosts)} active hosts saved to {filename}")


if __name__ == "__main__":
    target_domain = input("Enter a root domain (e.g., scanme.nmap.org or python.org): ").strip()
    if target_domain:
        asyncio.run(run_mapper(target_domain))

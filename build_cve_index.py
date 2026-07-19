"""Build cve-index.json for the IPSCOPE Firewall Patch-Gap Scanner.

Pulls known vulnerabilities for a curated set of firewall / security products from
the NVD 2.0 API (public, authoritative) and cross-references CISA's Known Exploited
Vulnerabilities (KEV) catalog to flag CVEs that are actively exploited in the wild.

Output is a compact JSON the static page reads client-side. No browser CORS/keys
needed at runtime — this runs server-side (locally or via GitHub Action).

Set NVD_API_KEY (free from https://nvd.nist.gov/developers/request-an-api-key)
as an env var / repo secret to lift rate limits; the script also works without it.
"""
import datetime
import json
import os
import time
import urllib.error
import urllib.request

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
API_KEY = os.environ.get("NVD_API_KEY")
PAGE = 2000
PAUSE = 0.8 if API_KEY else 6.5  # NVD: 50 req/30s with key, 5 req/30s without

# Firewall / network-security products, keyed by their NVD CPE product prefix.
PRODUCTS = [
    {"key": "fortinet-fortios",  "vendor": "Fortinet",           "product": "FortiOS (FortiGate)",         "cpe": "cpe:2.3:o:fortinet:fortios"},
    {"key": "paloalto-panos",    "vendor": "Palo Alto Networks", "product": "PAN-OS",                      "cpe": "cpe:2.3:o:paloaltonetworks:pan-os"},
    {"key": "cisco-asa",         "vendor": "Cisco",              "product": "ASA Software",               "cpe": "cpe:2.3:o:cisco:adaptive_security_appliance_software"},
    {"key": "cisco-ftd",         "vendor": "Cisco",              "product": "Firepower Threat Defense",   "cpe": "cpe:2.3:o:cisco:firepower_threat_defense"},
    {"key": "sonicwall-sonicos", "vendor": "SonicWall",          "product": "SonicOS",                    "cpe": "cpe:2.3:o:sonicwall:sonicos"},
    {"key": "juniper-junos",     "vendor": "Juniper",            "product": "Junos OS",                   "cpe": "cpe:2.3:o:juniper:junos"},
    {"key": "pfsense",           "vendor": "Netgate",            "product": "pfSense",                    "cpe": "cpe:2.3:a:pfsense:pfsense"},
]


def fetch(url):
    """GET JSON with retry/backoff — NVD throttles and occasionally 503s."""
    last = None
    for attempt in range(4):
        req = urllib.request.Request(url, headers={"User-Agent": "ipscope-cve/1.0"})
        if API_KEY:
            req.add_header("apiKey", API_KEY)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            last = e
            time.sleep(8 * (attempt + 1))
    raise last


def get_kev():
    try:
        d = fetch(KEV_URL)
        return {v["cveID"] for v in d.get("vulnerabilities", [])}
    except Exception as e:  # noqa: BLE001 - degrade gracefully
        print("  ! KEV fetch failed:", e)
        return set()


def cvss_of(cve):
    m = cve.get("metrics", {})
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(k):
            entry = m[k][0]
            c = entry["cvssData"]
            sev = (entry.get("baseSeverity") or c.get("baseSeverity") or "").upper()
            return round(c.get("baseScore", 0), 1), sev
    return None, ""


def ranges_for(cve, cpe_prefix):
    """Version conditions under which this product is vulnerable to the CVE."""
    out, seen = [], set()
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                if not m["criteria"].startswith(cpe_prefix + ":"):
                    continue
                r = {}
                parts = m["criteria"].split(":")
                ver = parts[5] if len(parts) > 5 else "*"
                if ver not in ("*", "-"):
                    r["eq"] = ver
                for field, short in (("versionStartIncluding", "gte"),
                                     ("versionStartExcluding", "gt"),
                                     ("versionEndIncluding", "lte"),
                                     ("versionEndExcluding", "lt")):
                    if m.get(field):
                        r[short] = m[field]
                if not r:
                    continue
                key = json.dumps(r, sort_keys=True)
                if key not in seen:
                    seen.add(key)
                    out.append(r)
    return out


def desc_of(cve):
    for d in cve.get("descriptions", []):
        if d["lang"] == "en":
            t = d["value"].strip()
            return t[:200] + ("…" if len(t) > 200 else "")
    return ""


def collect(cpe):
    items, start, total = [], 0, 1
    while start < total:
        url = f"{NVD}?virtualMatchString={cpe}&noRejected&resultsPerPage={PAGE}&startIndex={start}"
        d = fetch(url)
        total = d.get("totalResults", 0)
        items.extend(v["cve"] for v in d.get("vulnerabilities", []))
        start += PAGE
        time.sleep(PAUSE)
    return items


def main():
    print("Fetching CISA KEV catalog…")
    kev = get_kev()
    print(f"  KEV entries: {len(kev)}")

    out = {
        "generated": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%MZ"),
        "source": "NVD 2.0 API + CISA KEV",
        "products": [],
        "cves": {},
    }
    for p in PRODUCTS:
        print(f"Fetching {p['vendor']} {p['product']}…")
        try:
            cves = collect(p["cpe"])
        except Exception as e:  # noqa: BLE001
            print("  ! fetch failed:", e)
            cves = []
        recs = []
        for cve in cves:
            rngs = ranges_for(cve, p["cpe"])
            if not rngs:
                continue
            score, sev = cvss_of(cve)
            recs.append({
                "id": cve["id"],
                "cvss": score,
                "sev": sev,
                "pub": cve.get("published", "")[:10],
                "kev": cve["id"] in kev,
                "r": rngs,
                "d": desc_of(cve),
            })
        recs.sort(key=lambda x: (x["cvss"] or 0), reverse=True)
        out["products"].append({
            "key": p["key"], "vendor": p["vendor"], "product": p["product"],
            "count": len(recs), "kev": sum(1 for r in recs if r["kev"]),
        })
        out["cves"][p["key"]] = recs
        print(f"  {len(recs)} version-mapped CVEs ({sum(1 for r in recs if r['kev'])} on KEV)")
        time.sleep(PAUSE)

    with open("cve-index.json", "w", encoding="utf-8") as f:
        json.dump(out, f, separators=(",", ":"))
    size = os.path.getsize("cve-index.json") // 1024
    total = sum(pp["count"] for pp in out["products"])
    print(f"\nWrote cve-index.json — {total} CVEs across {len(out['products'])} products, {size} KB")


if __name__ == "__main__":
    main()

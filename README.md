# ✲ IPSCOPE — IP Threat & Geolocation Intelligence

**Look up any IP. See where it is — and whether to trust it.**

🔴 **Live tool:** https://sougatshekhar97-cpu.github.io/ipscope/

IPSCOPE is a zero-backend web app that takes any IPv4/IPv6 address and returns:

- **Geolocation** — country, region, city, coordinates, timezone (on an interactive map)
- **Network owner** — ASN, organisation, hosting/ISP type, RIR, abuse contact
- **Threat signals** — blacklist / known-abuser status, Tor exit, proxy, VPN, datacenter, bogon
- **A transparent risk score (0–100)** — a weighted sum of those signals, with the full
  breakdown shown on demand

> **Why this project is mine:** the risk score uses the same **weighted-signal scoring model**
> that runs through my other work — account health at Bharti Airtel,
> [PULSE-360](https://github.com/sougatshekhar97-cpu/pulse-360) for marketing channels, and
> [OPTICHAIN](https://github.com/sougatshekhar97-cpu/optichain) for suppliers. One methodology,
> now pointed at network reputation.

## Design notes

- **100% static, no server, no API keys.** It runs entirely in the browser on GitHub Pages,
  calling the keyless, CORS-enabled [ipapi.is](https://ipapi.is) intelligence API directly.
  Nothing to deploy, nothing to leak.
- **UI/UX** matches my portfolio: McKinsey-inspired palette (deep blue `#051C2C`, electric
  blue `#2251FF`, cool white) and the Newsreader serif.
- **Transparent, not a black box.** The risk score is an explicit weighted model you can expand
  and audit right in the UI.

## The risk model

| Signal | Weight |
|---|---|
| Blacklisted / known abuser | +42 |
| Bogon (unroutable / spoofed) | +35 |
| Tor exit node | +24 |
| Open / anonymising proxy | +16 |
| VPN endpoint | +11 |
| Datacenter / hosting | +8 |
| ASN abuser fraction | up to +25 |

Total capped at 100. **Bands:** 0 = Clean · 1–24 = Low · 25–54 = Elevated · 55+ = High risk.

## Honest limitations

Signals come from free public threat feeds and are **indicative, not definitive** — great for
triage and learning, not a substitute for a commercial threat-intelligence platform. Free
sources also occasionally over-flag large anonymised resolvers (e.g. public DNS).

## Run locally

It's a single file — open `index.html` in a browser, or serve the folder:

```bash
python -m http.server 8000
```

## License

MIT — see [LICENSE](LICENSE).

---

**Sougat Shekhar Hota** · [Portfolio](https://sougatshekhar97-cpu.github.io/portfolio/) ·
[PULSE-360](https://github.com/sougatshekhar97-cpu/pulse-360) ·
[OPTICHAIN](https://github.com/sougatshekhar97-cpu/optichain)

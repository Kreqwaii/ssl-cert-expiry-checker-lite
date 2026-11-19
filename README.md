# ssl-cert-expiry-checker-lite

**Bulk Domain SSL/TLS Certificate Expiry & Chain Inspector CLI (Lite)** — 100% Python 3.9+ standard-library utility (`ssl`, `socket`, `concurrent.futures`, `datetime`, `json`, `csv`, `argparse`) with zero third-party dependencies.

Утилита на чистом Python 3.9+ (без `pip install` и внешних библиотек): параллельно проверяет список доменов (`--domains` или файл), извлекает **CN / SANs / Issuer / Serial / TLS-протокол / Cipher / Chain Trust**, считает оставшиеся дни до истечения, маркирует статусы **`OK`** / **`WARNING`** / **`CRITICAL`** / **`EXPIRED`** / **`ERROR`**, поддерживает ненулевой exit code для CI/CD-алертов и экспорт в **Markdown, JSON и CSV**.

---

## Features

- **Zero dependencies** — pure Python 3.9+ `stdlib` (`ssl`, `socket`, `concurrent.futures`, `datetime`, `json`, `csv`, `argparse`).
- **Concurrent bulk scanning** — checks dozens or hundreds of domains in parallel via `ThreadPoolExecutor` (`--workers`, `--timeout`).
- **Full metadata extraction** — Common Name (`CN`), Subject Alternative Names (`SAN` DNS/IP/URI), Issuer (`O` / `CN`), Serial Number, TLS protocol version (e.g. `TLSv1.3`), Cipher suite, `notBefore` / `notAfter`, and `days_left`.
- **Expired & untrusted cert fallback** — includes a pure-Python ASN.1 DER X.509 parser so expired, self-signed, or hostname-mismatched certificates still report their CN, SANs, Issuer, and exact days expired instead of failing blindly.
- **Chain inspection** — verifies CA trust & hostname via OS trust store (`chain_trusted`), plus inspects intermediate chain length and expiry (Python 3.13+ `get_verified_chain` / `get_unverified_chain` with graceful fallback on 3.9–3.12).
- **Threshold statuses**:
  - `OK`: `days_left >= warn_days`
  - `WARNING`: `crit_days <= days_left < warn_days`
  - `CRITICAL`: `0 <= days_left < crit_days` (not yet expired)
  - `EXPIRED`: `not_after <= now` (`days_left <= 0`)
  - `ERROR`: DNS, TCP timeout, connection refused, or TLS handshake failure
- **CI/CD exit codes** — customizable `--fail-on {warning,critical,expired,error,none}` (default `critical`) and `--strict-trust` (fail on untrusted/self-signed chains).
- **Flexible output** — `--format markdown` (default), `--format json`, or `--format csv`, plus `--only-alerts` and `--output <file>`.

---

## Quick Start

Check multiple domains directly via CLI:

```bash
python ssl_check.py --domains github.com cloudflare.com example.com:443
```

Check targets from a file (`domains.example.txt`) with custom thresholds and JSON output:

```bash
python ssl_check.py --file domains.example.txt --warn-days 30 --crit-days 14 --format json
```

Export a CSV report and fail CI if any cert is in `WARNING` or worse or has an untrusted chain:

```bash
python ssl_check.py --file domains.example.txt --fail-on warning --strict-trust --format csv --output ssl_report.csv
```

Read targets from `stdin` and print only alerts:

```bash
cat domains.example.txt | python ssl_check.py --file - --only-alerts
```

Run the unit test suite (offline, mocked TLS):

```bash
py -B -m unittest -v
```

---

## CLI Options & Exit Codes

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-d`, `--domains` | — | Space- or comma-separated targets (`host`, `host:port`, `https://url`, `[ipv6]:port`) |
| `-f`, `--file` | — | File containing targets (`#` comments supported; `-` for stdin) |
| `-w`, `--warn-days` | `30` | Days threshold for `WARNING` status |
| `-c`, `--crit-days` | `14` | Days threshold for `CRITICAL` status |
| `-t`, `--timeout` | `5.0` | TCP/TLS timeout per domain in seconds |
| `-j`, `--workers` | `16` | Concurrent worker threads |
| `--format` | `markdown` | Output format: `markdown`, `json`, or `csv` |
| `-o`, `--output` | stdout | Write report to file path |
| `--fail-on` | `critical` | Exit `1` on `warning`, `critical`, `expired`, `error`, or `none` |
| `--strict-trust` | `false` | Also exit `1` if certificate chain verification fails |
| `--sort` | `urgency` | Sort order: `urgency`, `days`, `domain`, or `input` |
| `--only-alerts` | `false` | Show only non-`OK` targets in report output |

### Exit Codes

- `0`: All targets satisfy `--fail-on` (and `--strict-trust`, if enabled)
- `1`: One or more targets triggered an alert under the active policy
- `2`: Invalid CLI arguments or unreadable domain list

---

## Need 24/7 Self-Hosted Website Uptime, Latency, Keyword & SSL Monitoring with Instant Telegram Alerts & HTML Status Page?

This Lite CLI is ideal for one-off audits and CI/CD cron checks. If you want a **24/7 self-hosted monitoring service** with continuous HTTP/HTTPS uptime & latency tracking, keyword assertions, automated SSL expiry alerts, instant **Telegram notifications**, and a built-in **HTML Status Page**:

- **Get the Pro Full Version on FunPay:** https://funpay.com/lots/offer?id=82601762

---

## License

MIT License — see [LICENSE](LICENSE).

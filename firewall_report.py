#!/usr/bin/env python3
"""
Firewall Report - Linux iptables log analysis tool

A powerful, fast, and user-friendly Linux iptables firewall log analysis tool.
Parse iptables firewall logs, enrich IP addresses with GeoIP and Whois data,
and generate beautiful interactive HTML dashboards and JSON reports.

Features:
- Line-by-line log processing
- Gzip compressed log file support
- Date range filtering
- Flexible CLI with argparse
- Parallel GeoIP & Whois queries (with rate limiting and retry)
- TTL-based cache mechanism
- JSON output and enhanced HTML dashboard (summary + top-N)

Author: Cuma Kurt
GitHub: https://github.com/cumakurt/firewall_report
LinkedIn: https://www.linkedin.com/in/cuma-kurt-34414917/
License: GPL v3

Note: This tool is specifically designed to analyze Linux iptables firewall logs.
It expects log entries in the iptables log format.
"""

import re
import os
import sys
import socket
import json
import time
import gzip
import logging
import argparse
import subprocess
import ipaddress
from collections import Counter
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# -------------------------
# Ayarlar
# -------------------------
DEFAULT_LOG_FILE = "/var/log/firewall.log"
DEFAULT_OUTPUT_HTML = "/var/log/firewall_report.html"
DEFAULT_OUTPUT_JSON = None
CACHE_FILE = "/var/log/firewall_ipcache.json"
CACHE_TTL_SECONDS = 7 * 24 * 3600
MAX_THREADS = 10
REQUEST_DELAY_SECONDS = 0.0
RETRY_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 0.7
WHOIS_TIMEOUT_SECONDS = 5
IPINFO_TIMEOUT_SECONDS = 5
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "")

# -------------------------
# Logging
# -------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("firewall-report")

# -------------------------
# Regex
# -------------------------
pattern = re.compile(
    r"FW-(?P<prefix>[A-Z-]+):.*SRC=(?P<src>\S+).*DST=(?P<dst>\S+).*PROTO=(?P<proto>\S+)(?:.*DPT=(?P<dport>\d+))?"
)

# -------------------------
# Cache yükle
# -------------------------
def load_cache(cache_file: str, ttl_seconds: int):
    if not os.path.exists(cache_file):
        return {}
    try:
        with open(cache_file, "r") as f:
            data = json.load(f)
    except Exception:
        return {}
    if ttl_seconds <= 0:
        return data
    now_ts = int(time.time())
    filtered = {}
    for ip, info in data.items():
        ts = info.get("ts") or 0
        if now_ts - ts <= ttl_seconds:
            filtered[ip] = info
    return filtered


def save_cache(cache_file: str, data: dict):
    try:
        with open(cache_file, "w") as f:
            json.dump(data, f)
    except Exception as e:
        logger.warning("Cache yazılamadı: %s", e)


ip_cache = load_cache(CACHE_FILE, CACHE_TTL_SECONDS)

# -------------------------
# GeoIP ve Whois Fonksiyonları
# -------------------------
def _retry_sleep(attempt: int):
    time.sleep(RETRY_BACKOFF_SECONDS * (attempt + 1))


def try_ipinfo_api(ip):
    try:
        import urllib.request
        token_qs = f"?token={IPINFO_TOKEN}" if IPINFO_TOKEN else ""
        url = f"https://ipinfo.io/{ip}/json{token_qs}"
        for attempt in range(RETRY_ATTEMPTS):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=IPINFO_TIMEOUT_SECONDS) as resp:
                    data = json.load(resp)
                    country = data.get("country")
                    if country and str(country).strip():
                        return country
                    # ipinfo limit veya eksik bilgi durumunda Unknown yerine fallback deneyeceğiz
                    return "Unknown"
            except Exception:
                if attempt < RETRY_ATTEMPTS - 1:
                    _retry_sleep(attempt)
                else:
                    break
    except Exception:
        return "Unknown"


def try_ipapi_co(ip):
    try:
        import urllib.request
        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=IPINFO_TIMEOUT_SECONDS) as resp:
            data = json.load(resp)
            country = data.get("country")  # ISO-2
            if country and str(country).strip():
                return country
    except Exception:
        pass
    return "Unknown"


def try_ipwhois_app(ip):
    try:
        import urllib.request
        url = f"https://ipwhois.app/json/{ip}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=IPINFO_TIMEOUT_SECONDS) as resp:
            data = json.load(resp)
            country = data.get("country_code")
            if country and str(country).strip():
                return country
    except Exception:
        pass
    return "Unknown"


def try_ip_api_com(ip):
    try:
        import urllib.request
        url = f"http://ip-api.com/json/{ip}?fields=status,countryCode"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=IPINFO_TIMEOUT_SECONDS) as resp:
            data = json.load(resp)
            if data.get("status") == "success":
                country = data.get("countryCode")
                if country and str(country).strip():
                    return country
    except Exception:
        pass
    return "Unknown"


def resolve_country(ip):
    # Sıralı sağlayıcı denemeleri
    country = try_ipinfo_api(ip)
    if country and country != "Unknown":
        return country
    country = try_ipapi_co(ip)
    if country and country != "Unknown":
        return country
    country = try_ipwhois_app(ip)
    if country and country != "Unknown":
        return country
    country = try_ip_api_com(ip)
    return country

def parse_whois_text(txt):
    fields = ["OrgName", "org-name", "Org-Name", "owner", "netname", "descr"]
    for line in txt.splitlines():
        for fld in fields:
            if fld.lower() in line.lower():
                if ":" in line:
                    return line.split(":", 1)[1].strip()
    return None


def parse_whois_fields(txt):
    owner_fields = ["OrgName", "org-name", "Org-Name", "owner", "netname", "descr"]
    country_fields = ["country", "Country", "country-code", "countryCode", "Country Code", "c", "registrant country", "OrgCountry", "org-country"]
    owner_val = None
    country_val = None
    for raw in txt.splitlines():
        line = raw.strip()
        if not line or ":" not in line:
            continue
        key, val = line.split(":", 1)
        key_l = key.strip().lower()
        val_s = val.strip()
        # Bazı whois çıktılarında ülke değerleri iki harfli olabilir (TR, US) ya da ülke adı (Turkey)
        if not owner_val and any(key_l == f.lower() for f in owner_fields):
            owner_val = val_s
        if not country_val and any(key_l == f.lower() for f in country_fields):
            country_val = val_s
        if owner_val and country_val:
            break
    return {"owner": owner_val or "Unknown", "country": country_val or "Unknown"}

def try_whois_cli(ip):
    try:
        # Basit hız sınırlama
        time.sleep(REQUEST_DELAY_SECONDS)
        p = subprocess.run(["whois", ip], capture_output=True, text=True, timeout=WHOIS_TIMEOUT_SECONDS)
        out = p.stdout
        if out:
            # Hem owner hem country dene
            parsed_obj = parse_whois_fields(out)
            if parsed_obj:
                return parsed_obj
    except Exception:
        pass
    return {"owner": "Unknown", "country": "Unknown"}

def enrich_ip(ip):
    # Özel/yerel IP'leri dış sorgusuz işaretle
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
            info = {"country": "Local", "owner": "Private/Reserved", "ts": int(time.time())}
            ip_cache[ip] = info
            return ip, info
    except Exception:
        pass

    def _is_unknown_country(val: str | None) -> bool:
        if val is None:
            return True
        v = str(val).strip().lower()
        return v in ("", "none", "unknown")

    if ip in ip_cache:
        cached = ip_cache[ip]
        # Eğer önceden ülke bilgisi 'Unknown' ise tekrar dene ve güncelle
        if not _is_unknown_country(cached.get("country")) and cached.get("owner"):
            return ip, cached

    # Basit hız sınırlama
    time.sleep(REQUEST_DELAY_SECONDS)
    country = resolve_country(ip) if ENRICH_DO_GEO else "Unknown"
    owner = "Unknown"
    # Whois'i her zaman çalıştır (opsiyonel bayrak), ülke/owner varsa kullan
    if ENRICH_DO_WHOIS:
        who = try_whois_cli(ip)
        who_owner = who.get("owner") if isinstance(who, dict) else None
        if who_owner and who_owner.strip():
            owner = who_owner.strip()
        who_country = who.get("country") if isinstance(who, dict) else None
        # Normalize ülke: TR gibi kodları büyük harfe çevir; ülke adı gelirse kesmeden kullan
        if who_country and who_country.strip() and who_country.strip().lower() not in ("none", "unknown"):
            c = who_country.strip()
            country = c.upper() if len(c) <= 3 else c

    info = {"country": country, "owner": owner, "ts": int(time.time())}
    ip_cache[ip] = info
    return ip, info

# -------------------------
# Log Parse
# -------------------------
SYSLOG_DT_PATTERNS = [
    # e.g., "Jan 12 09:23:45 host ..."
    re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s"),
    # ISO-like: 2025-09-17T09:23:45Z or 2025-09-17 09:23:45
    re.compile(r"^(?P<date>\d{4}-\d{2}-\d{2})[T\s](?P<time>\d{2}:\d{2}:\d{2})")
]


def _parse_dt_from_line(line: str) -> datetime | None:
    for rx in SYSLOG_DT_PATTERNS:
        m = rx.search(line)
        if not m:
            continue
        gd = m.groupdict()
        try:
            if "mon" in gd:
                mon = gd["mon"]
                day = int(gd["day"]) if gd["day"] else 1
                tm = gd["time"]
                # Yılı tahmin et (şu anki yıl)
                year = datetime.now().year
                dt = datetime.strptime(f"{mon} {day} {year} {tm}", "%b %d %Y %H:%M:%S")
                return dt
            else:
                dt = datetime.strptime(f"{gd['date']} {gd['time']}", "%Y-%m-%d %H:%M:%S")
                return dt
        except Exception:
            continue
    return None


def _open_log(file_path: str):
    if file_path.endswith(".gz"):
        return gzip.open(file_path, "rt", errors="ignore")
    return open(file_path, "r", errors="ignore")


def parse_log(file_path, start_dt: datetime | None = None, end_dt: datetime | None = None):
    logger.info("Log dosyası işleniyor: %s", file_path)
    prefix_counter = Counter()
    src_counter = Counter()
    dst_counter = Counter()
    proto_counter = Counter()
    dport_counter = Counter()

    with _open_log(file_path) as f:
        for line in f:
            # Hızlı ön filtre: gerekli tokenlar yoksa regex yapma
            if "FW-" not in line or "SRC=" not in line or "PROTO=" not in line:
                continue
            # Tarih filtresi
            if start_dt or end_dt:
                dt = _parse_dt_from_line(line)
                if dt is not None:
                    if start_dt and dt < start_dt:
                        continue
                    if end_dt and dt > end_dt:
                        continue
            m = pattern.search(line)
            if not m:
                continue
            d = m.groupdict()
            if d.get("prefix"): prefix_counter[d["prefix"]] += 1
            if d.get("src"): src_counter[d["src"]] += 1
            if d.get("dst"): dst_counter[d["dst"]] += 1
            if d.get("proto"): proto_counter[d["proto"]] += 1
            if d.get("dport"): dport_counter[d["dport"]] += 1

    logger.info("Parse tamamlandı. Kaynak IP: %d, Hedef IP: %d, Port: %d",
                len(src_counter), len(dst_counter), len(dport_counter))
    return prefix_counter, src_counter, dst_counter, proto_counter, dport_counter

# -------------------------
# Servis ismi
# -------------------------
_service_cache = {}
_services_map = None  # Lazy-loaded mapping from /etc/services


def _load_services_map():
    global _services_map
    if _services_map is not None:
        return _services_map
    mapping = {}
    try:
        with open("/etc/services", "r", encoding="utf-8", errors="ignore") as sf:
            for raw in sf:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                # Example: ssh            22/tcp
                #          domain         53/udp
                #          kerberos       88/tcp   kerberos-sec
                parts = line.split()
                if len(parts) < 2:
                    continue
                name = parts[0]
                port_proto = parts[1]
                if "/" not in port_proto:
                    continue
                port_str, proto = port_proto.split("/", 1)
                try:
                    pnum = int(port_str)
                except Exception:
                    continue
                mapping[(pnum, proto.lower())] = name
    except Exception:
        mapping = {}
    _services_map = mapping
    return _services_map


def get_service_name(port, proto="tcp"):
    try:
        key = (int(port), str(proto).lower())
        # First, check memoized cache
        if key in _service_cache:
            return _service_cache[key]
        # Then, consult /etc/services map
        services = _load_services_map()
        if key in services:
            _service_cache[key] = services[key]
            return services[key]
        # Fallback to socket database
        name = socket.getservbyport(key[0], key[1])
        _service_cache[key] = name
        return name
    except Exception:
        return "Unknown"

# -------------------------
# HTML Rapor
# -------------------------
def build_html(prefix_counter, src_counter, dst_counter, proto_counter, dport_counter, enriched_src, country_counter, output_file, top_n=None):
    logger.info("HTML raporu oluşturuluyor...")

    # Plot verileri
    plot_data = {
        "country_labels": list(country_counter.keys()),
        "country_values": list(country_counter.values()),
        "prefix_labels": list(prefix_counter.keys()),
        "prefix_values": list(prefix_counter.values()),
        "proto_labels": list(proto_counter.keys()),
        "proto_values": list(proto_counter.values()),
        "port_labels": list(dport_counter.keys()),
        "port_values": [dport_counter[p] for p in dport_counter.keys()],
    }

    # HTML
    html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Firewall Log Dashboard</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css">
<link rel="stylesheet" href="https://cdn.datatables.net/buttons/2.4.2/css/buttons.bootstrap5.min.css">
<link rel="stylesheet" href="https://cdn.datatables.net/fixedheader/3.4.0/css/fixedHeader.bootstrap5.min.css">
<link rel="stylesheet" href="https://cdn.datatables.net/responsive/2.5.0/css/responsive.bootstrap5.min.css">
<script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>
<script src="https://cdn.datatables.net/buttons/2.4.2/js/dataTables.buttons.min.js"></script>
<script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.bootstrap5.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>
<script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.html5.min.js"></script>
<script src="https://cdn.datatables.net/fixedheader/3.4.0/js/dataTables.fixedHeader.min.js"></script>
<script src="https://cdn.datatables.net/responsive/2.5.0/js/dataTables.responsive.min.js"></script>
<script src="https://cdn.datatables.net/responsive/2.5.0/js/responsive.bootstrap5.min.js"></script>
<script src="https://cdn.plot.ly/plotly-2.26.0.min.js"></script>
<style>
body {{ background: linear-gradient(180deg, #f8f9fa 0%, #eef2f7 100%); color: #212529; }}
.summary {{ display:flex; gap:16px; margin: 16px 0; flex-wrap: wrap; }}
.card-stat {{ padding:12px 16px; border-radius:10px; min-width: 180px; color:#fff; box-shadow: 0 2px 8px rgba(0,0,0,.06); }}
.card-stat.primary {{ background: linear-gradient(135deg,#4e79ff,#3264ff); }}
.card-stat.success {{ background: linear-gradient(135deg,#28a745,#20c997); }}
.card-stat.info {{ background: linear-gradient(135deg,#17a2b8,#0dcaf0); }}
.card-stat.warning {{ background: linear-gradient(135deg,#ffc107,#ffb300); color:#212529; }}
.card-stat.danger {{ background: linear-gradient(135deg,#dc3545,#ff4d5a); }}
.tab-content {{ margin-top: 16px; }}
.dataTables_wrapper .dt-buttons {{ margin-bottom: 8px; }}
</style>
</head>
<body>
<nav class="navbar navbar-expand-lg bg-body-tertiary border-bottom">
  <div class="container-fluid">
    <span class="navbar-brand">Firewall Log Dashboard</span>
  </div>
</nav>

<div class="container py-3">
  <div class="d-flex justify-content-between align-items-center">
    <h1 class="h3 m-0">Rapor</h1>
    <small>Rapor tarihi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small>
  </div>

  <div class="summary">
    <div class="card-stat primary"><b>Toplam Kaynak IP</b><br>{len(src_counter)}</div>
    <div class="card-stat info"><b>Toplam Hedef IP</b><br>{len(dst_counter)}</div>
    <div class="card-stat success"><b>Toplam Protokol</b><br>{len(proto_counter)}</div>
    <div class="card-stat warning"><b>Toplam Port</b><br>{len(dport_counter)}</div>
    <div class="card-stat danger"><b>Toplam Olay</b><br>{sum(prefix_counter.values())}</div>
    <div class="card-stat info"><b>Ülke Sayısı</b><br>{len(country_counter)}</div>
  </div>

  <ul class="nav nav-tabs" id="reportTabs" role="tablist">
    <li class="nav-item" role="presentation">
      <button class="nav-link active" id="tab-sources" data-bs-toggle="tab" data-bs-target="#pane-sources" type="button" role="tab">Kaynak IP'ler</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-proto" data-bs-toggle="tab" data-bs-target="#pane-proto" type="button" role="tab">Protokoller</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-ports" data-bs-toggle="tab" data-bs-target="#pane-ports" type="button" role="tab">Portlar</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-charts" data-bs-toggle="tab" data-bs-target="#pane-charts" type="button" role="tab">Grafikler</button>
    </li>
  </ul>

  <div class="tab-content" id="reportTabsContent">
    <div class="tab-pane fade show active" id="pane-sources" role="tabpanel" aria-labelledby="tab-sources">
      <table id="src" class="datatable table table-striped table-hover table-sm nowrap" style="width:100%">
      <thead><tr><th>#</th><th>IP</th><th>Adet</th><th>Ülke</th><th>Whois</th></tr></thead><tbody>
"""
    rows_src = sorted(enriched_src, key=lambda x: x["count"], reverse=True)
    if top_n:
        rows_src = rows_src[:top_n]
    for idx, rec in enumerate(rows_src, start=1):
        html += f"<tr><td>{idx}</td><td>{rec['ip']}</td><td>{rec['count']}</td><td>{rec['country']}</td><td>{rec['owner']}</td></tr>\n"

    html += """
      </tbody></table>
    </div>
    <div class=\"tab-pane fade\" id=\"pane-proto\" role=\"tabpanel\" aria-labelledby=\"tab-proto\">
      <table id=\"proto\" class=\"datatable table table-striped table-hover table-sm nowrap\" style=\"width:100%\">
      <thead><tr><th>#</th><th>Protokol</th><th>Adet</th></tr></thead><tbody>
"""
    rows_proto = proto_counter.most_common(top_n if top_n else None)
    for idx, (proto, cnt) in enumerate(rows_proto, start=1):
        html += f"<tr><td>{idx}</td><td>{proto}</td><td>{cnt}</td></tr>\n"

    html += """
      </tbody></table>
    </div>
    <div class=\"tab-pane fade\" id=\"pane-ports\" role=\"tabpanel\" aria-labelledby=\"tab-ports\">
      <table id=\"ports\" class=\"datatable table table-striped table-hover table-sm nowrap\" style=\"width:100%\">
      <thead><tr><th>#</th><th>Port</th><th>Servis</th><th>Adet</th></tr></thead><tbody>
"""
    rows_ports = dport_counter.most_common(top_n if top_n else None)
    for idx, (port, cnt) in enumerate(rows_ports, start=1):
        service = get_service_name(port)
        html += f"<tr><td>{idx}</td><td>{port}</td><td>{service.upper()}</td><td>{cnt}</td></tr>\n"

    html += f"""
      </tbody></table>
    </div>
    <div class=\"tab-pane fade\" id=\"pane-charts\" role=\"tabpanel\" aria-labelledby=\"tab-charts\">
      <div class=\"row g-3\">
        <div class=\"col-12 col-lg-6\"><div id=\"chart_country\"></div></div>
        <div class=\"col-12 col-lg-6\"><div id=\"chart_prefix\"></div></div>
        <div class=\"col-12 col-lg-6\"><div id=\"chart_proto\"></div></div>
        <div class=\"col-12 col-lg-6\"><div id=\"chart_ports\"></div></div>
      </div>
    </div>
  </div>
</div>

<script>
$(document).ready(function() {{
  // Kaynak IP tablosuna ayrıca ayrı Excel butonu ekle (diğerleri ortak ayarı kullanır)
  $('#src').DataTable({{
    responsive: true,
    fixedHeader: true,
    pageLength: 10,
    lengthMenu: [ [10, 20, 30, 50, 100, -1], [10, 20, 30, 50, 100, 'All'] ],
    dom: 'lBfrtip',
    buttons: [
      {{ extend: 'excelHtml5', title: null, exportOptions: {{ columns: ':visible' }} }}
    ]
  }});
  // Diğer tablolar
  $('#proto, #ports').DataTable({{
    responsive: true,
    fixedHeader: true,
    pageLength: 10,
    lengthMenu: [ [10, 20, 30, 50, 100, -1], [10, 20, 30, 50, 100, 'All'] ],
    dom: 'lfrtip'
  }});
}});

var plotData = {json.dumps(plot_data)};

Plotly.newPlot('chart_country', [{{labels: plotData.country_labels, values: plotData.country_values, type: 'pie'}}], {{title:'Ülke Dağılımı'}});
Plotly.newPlot('chart_prefix', [{{x: plotData.prefix_labels, y: plotData.prefix_values, type: 'bar'}}], {{title:'Prefix Dağılımı'}});
Plotly.newPlot('chart_proto', [{{x: plotData.proto_labels, y: plotData.proto_values, type: 'bar'}}], {{title:'Protokol Dağılımı'}});
Plotly.newPlot('chart_ports', [{{x: plotData.port_labels, y: plotData.port_values, type: 'bar'}}], {{title:'Port Dağılımı'}});
</script>

</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
    logger.info("Rapor yazıldı: %s", output_file)

# -------------------------
# Ana Çalışma
# -------------------------
def _parse_args():
    parser = argparse.ArgumentParser(description="Firewall log analiz aracı")
    parser.add_argument("--log-file", default=DEFAULT_LOG_FILE, help="Girdi log dosyası (gz destekli)")
    parser.add_argument("--output-html", default=DEFAULT_OUTPUT_HTML, help="HTML çıktı dosyası")
    parser.add_argument("--output-json", default=DEFAULT_OUTPUT_JSON, help="JSON çıktı dosyası (opsiyonel)")
    parser.add_argument("--cache-file", default=CACHE_FILE, help="IP cache dosyası")
    parser.add_argument("--cache-ttl", type=int, default=CACHE_TTL_SECONDS, help="Cache TTL (saniye)")
    parser.add_argument("--max-threads", type=int, default=MAX_THREADS, help="Paralel iş parçaçığı sayısı")
    parser.add_argument("--top-n", type=int, default=50, help="Tablolarda gösterilecek maksimum satır sayısı (0=hepsi)")
    parser.add_argument("--start", help="Başlangıç tarihi (YYYY-MM-DD veya YYYY-MM-DDTHH:MM:SS)")
    parser.add_argument("--end", help="Bitiş tarihi (YYYY-MM-DD veya YYYY-MM-DDTHH:MM:SS)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG","INFO","WARNING","ERROR"], help="Log seviyesi")
    # Performans/zenginleştirme
    parser.add_argument("--enrich-top-n", type=int, default=200, help="Zenginleştirilecek en çok görülen kaynak IP sayısı (0=hepsi)")
    parser.add_argument("--no-whois", action="store_true", help="Whois sorgularını kapat")
    parser.add_argument("--no-geo", action="store_true", help="GeoIP (ipinfo) sorgularını kapat")
    parser.add_argument("--request-delay", type=float, default=REQUEST_DELAY_SECONDS, help="Dış istekler arası gecikme (s)")
    parser.add_argument("--whois-timeout", type=int, default=WHOIS_TIMEOUT_SECONDS, help="Whois zaman aşımı (s)")
    parser.add_argument("--ipinfo-timeout", type=int, default=IPINFO_TIMEOUT_SECONDS, help="ipinfo zaman aşımı (s)")
    parser.add_argument("--ipinfo-token", default=os.environ.get("IPINFO_TOKEN", ""), help="ipinfo akses token (opsiyonel)")
    return parser.parse_args()


def _parse_date(s: str | None) -> datetime | None:
    if not s:
        return None
    fmts = ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"]
    for fmt in fmts:
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue
    raise ValueError(f"Tarih formatı desteklenmiyor: {s}")


def main():
    args = _parse_args()
    logger.setLevel(getattr(logging, args.log_level))

    global CACHE_FILE, CACHE_TTL_SECONDS, MAX_THREADS
    CACHE_FILE = args.cache_file
    CACHE_TTL_SECONDS = args.cache_ttl
    MAX_THREADS = args.max_threads
    # Zaman aşımı / gecikme ayarları
    global REQUEST_DELAY_SECONDS, WHOIS_TIMEOUT_SECONDS, IPINFO_TIMEOUT_SECONDS, IPINFO_TOKEN
    REQUEST_DELAY_SECONDS = max(0.0, float(args.request_delay))
    WHOIS_TIMEOUT_SECONDS = int(args.whois_timeout)
    IPINFO_TIMEOUT_SECONDS = int(args.ipinfo_timeout)
    IPINFO_TOKEN = args.ipinfo_token or os.environ.get("IPINFO_TOKEN", "")
    # Zenginleştirme bayrakları
    global ENRICH_DO_WHOIS, ENRICH_DO_GEO
    ENRICH_DO_WHOIS = not args.no_whois
    ENRICH_DO_GEO = not args.no_geo

    # Cache'i yeniden yükle (TTL değişmiş olabilir)
    global ip_cache
    ip_cache = load_cache(CACHE_FILE, CACHE_TTL_SECONDS)

    start_dt = _parse_date(args.start)
    end_dt = _parse_date(args.end)
    if end_dt and start_dt and end_dt < start_dt:
        raise ValueError("Bitiş tarihi başlangıçtan önce olamaz")

    prefix_counter, src_counter, dst_counter, proto_counter, dport_counter = parse_log(
        args.log_file, start_dt=start_dt, end_dt=end_dt
    )

    logger.info("IP bilgileri enrich ediliyor...")
    enriched_src = []
    country_counter = Counter()

    # En çok görülen IP'lerle sınırlı enrich
    items_sorted = sorted(src_counter.items(), key=lambda kv: kv[1], reverse=True)
    enrich_limit = args.enrich_top_n if args.enrich_top_n and args.enrich_top_n > 0 else len(items_sorted)
    to_enrich = [ip for ip, _ in items_sorted[:enrich_limit]]

    def _norm(val: str | None, fallback: str = "Unknown") -> str:
        if val is None:
            return fallback
        if isinstance(val, str) and val.strip().lower() in ("", "none", "null", "unknown"):
            return fallback
        return str(val)

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(enrich_ip, ip): ip for ip in to_enrich}
        for future in as_completed(futures):
            ip, info = future.result()
            count = src_counter.get(ip, 0)
            country = _norm(info.get("country"), "Unknown")
            owner = _norm(info.get("owner"), "Unknown")
            enriched_src.append({"ip": ip, "count": count, "country": country, "owner": owner})
            country_counter[country] += count

    # Zenginleştirme dışında kalan IP'leri hızlıca ekle (cache varsa kullan)
    skipped = set(src_counter.keys()) - set(to_enrich)
    for ip in skipped:
        count = src_counter[ip]
        info = ip_cache.get(ip, {})
        country = _norm(info.get("country"), "Unknown")
        owner = _norm(info.get("owner"), "Unknown")
        enriched_src.append({"ip": ip, "count": count, "country": country, "owner": owner})
        country_counter[country] += count

    save_cache(CACHE_FILE, ip_cache)

    top_n = args.top_n if args.top_n and args.top_n > 0 else None

    if args.output_html:
        build_html(prefix_counter, src_counter, dst_counter, proto_counter, dport_counter, enriched_src, country_counter, args.output_html, top_n=top_n)

    if args.output_json:
        logger.info("JSON çıktısı yazılıyor: %s", args.output_json)
        data = {
            "generated_at": datetime.now().isoformat(),
            "log_file": args.log_file,
            "start": start_dt.isoformat() if start_dt else None,
            "end": end_dt.isoformat() if end_dt else None,
            "prefix": dict(prefix_counter),
            "proto": dict(proto_counter),
            "ports": dict(dport_counter),
            "countries": dict(country_counter),
            "sources": enriched_src,
        }
        with open(args.output_json, "w", encoding="utf-8") as jf:
            json.dump(data, jf, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()

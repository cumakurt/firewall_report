# 🔥 Firewall Report

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-GPL-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/Code%20Style-PEP8-orange.svg)](https://www.python.org/dev/peps/pep-0008/)
[![GitHub](https://img.shields.io/badge/GitHub-Repository-blue.svg)](https://github.com/cumakurt/firewall_report)

A powerful, fast, and user-friendly **Linux iptables firewall log analysis tool**. Parse iptables firewall logs, enrich IP addresses with GeoIP and Whois data, and generate beautiful interactive HTML dashboards and JSON reports.

> **Note:** This tool is specifically designed to analyze **Linux iptables firewall logs**. It expects log entries in the iptables log format.

---

## 📋 Table of Contents

- [English](#-english)
  - [Features](#features)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Examples](#examples)
  - [Output](#output)
  - [Performance Tips](#performance-tips)
  - [Contributing](#contributing)
  - [License](#license)
- [Türkçe](#-türkçe)
  - [Özellikler](#özellikler)
  - [Kurulum](#kurulum)
  - [Kullanım](#kullanım)
  - [Örnekler](#örnekler)
  - [Çıktı](#çıktı)
  - [Performans İpuçları](#performans-ipuçları)
  - [Katkıda Bulunma](#katkıda-bulunma)
  - [Lisans](#lisans)

---

## 🇬🇧 English

### Features

- ✅ **Linux iptables Log Analysis**: Specifically designed for Linux iptables firewall logs
- ✅ **Gzip Support**: Read compressed log files (`.gz` files)
- ✅ **Date Range Filtering**: Filter logs by start/end dates
- ✅ **Parallel IP Enrichment**: Multi-threaded GeoIP and Whois lookups with rate limiting
- ✅ **TTL-based Caching**: Intelligent IP cache with configurable TTL
- ✅ **Multiple GeoIP Providers**: Fallback support for ipinfo.io, ipapi.co, ipwhois.app, ip-api.com
- ✅ **Interactive HTML Dashboard**: Beautiful dashboard with DataTables, Plotly charts, and responsive design
- ✅ **JSON Export**: Machine-readable JSON output for further processing
- ✅ **Service Name Resolution**: Automatic port-to-service name mapping
- ✅ **Private IP Detection**: Automatic detection and labeling of private/reserved IPs
- ✅ **Flexible CLI**: Comprehensive command-line interface with argparse

### Installation

**Requirements:**
- Linux system with iptables firewall logs
- Python 3.9 or higher
- `whois` CLI tool (for Whois lookups)

**System Dependencies:**

Debian/Ubuntu:
```bash
sudo apt-get update && sudo apt-get install -y whois
```

**Python Dependencies:**

This tool uses only Python standard library - no additional Python packages required!

### Usage

**Basic Usage:**
```bash
python3 firewall_report.py \
  --log-file /var/log/firewall.log \
  --output-html /var/log/firewall_report.html
```

**Full Example:**
```bash
python3 firewall_report.py \
  --log-file /var/log/firewall.log \
  --output-html /var/log/firewall_report.html \
  --output-json /var/log/firewall_report.json \
  --cache-file /var/log/firewall_ipcache.json \
  --cache-ttl 604800 \
  --max-threads 10 \
  --top-n 100 \
  --start 2025-09-01 \
  --end 2025-09-17 \
  --log-level INFO \
  --enrich-top-n 200 \
  --request-delay 0.0 \
  --whois-timeout 5 \
  --ipinfo-timeout 5
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--log-file` | Input log file (supports `.gz` files) | `/var/log/firewall.log` |
| `--output-html` | HTML output file | `/var/log/firewall_report.html` |
| `--output-json` | JSON output file (optional) | `None` |
| `--cache-file` | IP cache file path | `/var/log/firewall_ipcache.json` |
| `--cache-ttl` | Cache TTL in seconds | `604800` (7 days) |
| `--max-threads` | Number of parallel threads | `10` |
| `--top-n` | Maximum rows in tables (0=all) | `50` |
| `--start` | Start date (`YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SS`) | `None` |
| `--end` | End date (`YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SS`) | `None` |
| `--log-level` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) | `INFO` |
| `--enrich-top-n` | Number of top IPs to enrich (0=all) | `200` |
| `--no-whois` | Disable Whois lookups (faster) | `False` |
| `--no-geo` | Disable GeoIP lookups | `False` |
| `--request-delay` | Delay between external requests (seconds) | `0.0` |
| `--whois-timeout` | Whois timeout (seconds) | `5` |
| `--ipinfo-timeout` | IPInfo timeout (seconds) | `5` |
| `--ipinfo-token` | IPInfo API token (optional, from `IPINFO_TOKEN` env var) | `""` |

### Examples

**Analyze last 24 hours:**
```bash
python3 firewall_report.py \
  --log-file /var/log/firewall.log \
  --output-html /var/log/firewall_report.html \
  --start "$(date -d 'yesterday' +%F)" \
  --end "$(date +%F)"
```

**Analyze gzipped log file:**
```bash
python3 firewall_report.py \
  --log-file /var/log/firewall.log.1.gz \
  --output-html report.html \
  --output-json report.json
```

**Fast mode (no enrichment):**
```bash
python3 firewall_report.py \
  --enrich-top-n 100 \
  --no-whois \
  --no-geo
```

**Cron job example (daily at 1 AM):**
```cron
0 1 * * * /usr/bin/python3 /path/to/firewall_report.py \
  --log-file /var/log/firewall.log \
  --output-html /var/log/firewall_report.html \
  --cache-file /var/log/firewall_ipcache.json \
  --top-n 200 >> /var/log/firewall_report_cron.log 2>&1
```

### Output

**HTML Dashboard:**
- Interactive DataTables with search, sort, and pagination
- Plotly charts for country distribution, protocols, ports, and prefixes
- Responsive design with Bootstrap 5
- Export to Excel functionality
- Summary statistics cards

**JSON Report:**
- Machine-readable format
- Aggregated statistics (counters, top IPs)
- Enriched IP information (country, owner)
- Metadata (generation time, date range, log file)

### Performance Tips

- **Private IPs**: Automatically detected and labeled as "Local" without external queries
- **Caching**: IP information is cached with TTL to reduce API calls
- **Top-N Enrichment**: Use `--enrich-top-n` to limit enrichment to most frequent IPs
- **Threading**: Adjust `--max-threads` based on your network capacity
- **Rate Limiting**: Use `--request-delay` to avoid overwhelming external APIs
- **Disable Features**: Use `--no-whois` or `--no-geo` for faster processing
- **Table Limits**: Use `--top-n` to improve browser performance with large datasets

### Log Format

This tool is designed specifically for **Linux iptables firewall logs**. It expects log entries in the iptables log format:

```
FW-<PREFIX>: ... SRC=<source_ip> ... DST=<dest_ip> ... PROTO=<protocol> ... DPT=<port> ...
```

Example:
```
FW-BLOCK: IN=eth0 OUT= MAC=... SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP DPT=443
```

**Important:** This tool only works with Linux iptables log format. Other firewall log formats (pfSense, Windows Firewall, etc.) are not supported.

### Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### License

This project is licensed under the GPL License - see the [LICENSE](LICENSE) file for details.

---

## 🇹🇷 Türkçe

> **Not:** Bu araç özellikle **Linux iptables firewall loglarını** analiz etmek için tasarlanmıştır. iptables log formatındaki log girişlerini bekler.

### Özellikler

- ✅ **Linux iptables Log Analizi**: Özellikle Linux iptables firewall logları için tasarlanmıştır
- ✅ **Gzip Desteği**: Sıkıştırılmış log dosyalarını okuyabilme (`.gz` dosyaları)
- ✅ **Tarih Aralığı Filtreleme**: Başlangıç/bitiş tarihlerine göre log filtreleme
- ✅ **Paralel IP Zenginleştirme**: Hız sınırlamalı çoklu iş parçacıklı GeoIP ve Whois sorguları
- ✅ **TTL Tabanlı Önbellek**: Yapılandırılabilir TTL ile akıllı IP önbelleği
- ✅ **Çoklu GeoIP Sağlayıcı**: ipinfo.io, ipapi.co, ipwhois.app, ip-api.com için yedek destek
- ✅ **İnteraktif HTML Dashboard**: DataTables, Plotly grafikleri ve duyarlı tasarım ile güzel dashboard
- ✅ **JSON Dışa Aktarma**: Daha fazla işleme için makine tarafından okunabilir JSON çıktısı
- ✅ **Servis Adı Çözümleme**: Otomatik port-servis adı eşleştirmesi
- ✅ **Özel IP Algılama**: Özel/rezerve IP'lerin otomatik algılanması ve etiketlenmesi
- ✅ **Esnek CLI**: Argparse ile kapsamlı komut satırı arayüzü

### Kurulum

**Gereksinimler:**
- iptables firewall logları olan Linux sistemi
- Python 3.9 veya üzeri
- `whois` CLI aracı (Whois sorguları için)

**Sistem Bağımlılıkları:**

Debian/Ubuntu:
```bash
sudo apt-get update && sudo apt-get install -y whois
```

**Python Bağımlılıkları:**

Bu araç sadece Python standart kütüphanesini kullanır - ek Python paketi gerekmez!

### Kullanım

**Temel Kullanım:**
```bash
python3 firewall_report.py \
  --log-file /var/log/firewall.log \
  --output-html /var/log/firewall_report.html
```

**Tam Örnek:**
```bash
python3 firewall_report.py \
  --log-file /var/log/firewall.log \
  --output-html /var/log/firewall_report.html \
  --output-json /var/log/firewall_report.json \
  --cache-file /var/log/firewall_ipcache.json \
  --cache-ttl 604800 \
  --max-threads 10 \
  --top-n 100 \
  --start 2025-09-01 \
  --end 2025-09-17 \
  --log-level INFO \
  --enrich-top-n 200 \
  --request-delay 0.0 \
  --whois-timeout 5 \
  --ipinfo-timeout 5
```

### Komut Satırı Argümanları

| Argüman | Açıklama | Varsayılan |
|---------|----------|------------|
| `--log-file` | Girdi log dosyası (`.gz` dosyaları desteklenir) | `/var/log/firewall.log` |
| `--output-html` | HTML çıktı dosyası | `/var/log/firewall_report.html` |
| `--output-json` | JSON çıktı dosyası (opsiyonel) | `None` |
| `--cache-file` | IP önbellek dosyası yolu | `/var/log/firewall_ipcache.json` |
| `--cache-ttl` | Önbellek TTL (saniye) | `604800` (7 gün) |
| `--max-threads` | Paralel iş parçacığı sayısı | `10` |
| `--top-n` | Tablolarda maksimum satır sayısı (0=hepsi) | `50` |
| `--start` | Başlangıç tarihi (`YYYY-MM-DD` veya `YYYY-MM-DDTHH:MM:SS`) | `None` |
| `--end` | Bitiş tarihi (`YYYY-MM-DD` veya `YYYY-MM-DDTHH:MM:SS`) | `None` |
| `--log-level` | Log seviyesi (`DEBUG`, `INFO`, `WARNING`, `ERROR`) | `INFO` |
| `--enrich-top-n` | Zenginleştirilecek en çok görülen IP sayısı (0=hepsi) | `200` |
| `--no-whois` | Whois sorgularını kapat (daha hızlı) | `False` |
| `--no-geo` | GeoIP sorgularını kapat | `False` |
| `--request-delay` | Dış istekler arası gecikme (saniye) | `0.0` |
| `--whois-timeout` | Whois zaman aşımı (saniye) | `5` |
| `--ipinfo-timeout` | IPInfo zaman aşımı (saniye) | `5` |
| `--ipinfo-token` | IPInfo API token (opsiyonel, `IPINFO_TOKEN` env değişkeninden) | `""` |

### Örnekler

**Son 24 saati analiz et:**
```bash
python3 firewall_report.py \
  --log-file /var/log/firewall.log \
  --output-html /var/log/firewall_report.html \
  --start "$(date -d 'yesterday' +%F)" \
  --end "$(date +%F)"
```

**Gzip log dosyasını analiz et:**
```bash
python3 firewall_report.py \
  --log-file /var/log/firewall.log.1.gz \
  --output-html report.html \
  --output-json report.json
```

**Hızlı mod (zenginleştirme yok):**
```bash
python3 firewall_report.py \
  --enrich-top-n 100 \
  --no-whois \
  --no-geo
```

**Cron job örneği (her gün saat 01:00):**
```cron
0 1 * * * /usr/bin/python3 /path/to/firewall_report.py \
  --log-file /var/log/firewall.log \
  --output-html /var/log/firewall_report.html \
  --cache-file /var/log/firewall_ipcache.json \
  --top-n 200 >> /var/log/firewall_report_cron.log 2>&1
```

### Çıktı

**HTML Dashboard:**
- Arama, sıralama ve sayfalama ile interaktif DataTables
- Ülke dağılımı, protokoller, portlar ve prefixler için Plotly grafikleri
- Bootstrap 5 ile duyarlı tasarım
- Excel'e dışa aktarma işlevselliği
- Özet istatistik kartları

**JSON Rapor:**
- Makine tarafından okunabilir format
- Toplanmış istatistikler (sayaçlar, en çok görülen IP'ler)
- Zenginleştirilmiş IP bilgileri (ülke, sahip)
- Meta veriler (oluşturulma zamanı, tarih aralığı, log dosyası)

### Performans İpuçları

- **Özel IP'ler**: Otomatik algılanır ve dış sorgu olmadan "Local" olarak etiketlenir
- **Önbellekleme**: IP bilgileri API çağrılarını azaltmak için TTL ile önbelleğe alınır
- **Top-N Zenginleştirme**: En sık görülen IP'lerle sınırlamak için `--enrich-top-n` kullanın
- **İş Parçacığı**: Ağ kapasitenize göre `--max-threads` değerini ayarlayın
- **Hız Sınırlama**: Dış API'leri bunaltmamak için `--request-delay` kullanın
- **Özellikleri Kapatma**: Daha hızlı işleme için `--no-whois` veya `--no-geo` kullanın
- **Tablo Limitleri**: Büyük veri setlerinde tarayıcı performansını artırmak için `--top-n` kullanın

### Log Formatı

Bu araç özellikle **Linux iptables firewall logları** için tasarlanmıştır. iptables log formatındaki log girişlerini bekler:

```
FW-<PREFIX>: ... SRC=<source_ip> ... DST=<dest_ip> ... PROTO=<protocol> ... DPT=<port> ...
```

Örnek:
```
FW-BLOCK: IN=eth0 OUT= MAC=... SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP DPT=443
```

**Önemli:** Bu araç sadece Linux iptables log formatı ile çalışır. Diğer firewall log formatları (pfSense, Windows Firewall, vb.) desteklenmez.

### Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen bir Pull Request göndermekten çekinmeyin.

1. Repository'yi fork edin
2. Özellik dalınızı oluşturun (`git checkout -b feature/HarikaOzellik`)
3. Değişikliklerinizi commit edin (`git commit -m 'Harika bir özellik ekle'`)
4. Dalı push edin (`git push origin feature/HarikaOzellik`)
5. Bir Pull Request açın

### Lisans

Bu proje GPL Lisansı altında lisanslanmıştır - detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

## 📞 Support

If you encounter any issues or have questions, please open an issue on GitHub.

Herhangi bir sorunla karşılaşırsanız veya sorularınız varsa, lütfen GitHub'da bir issue açın.

**GitHub Repository:** [https://github.com/cumakurt/firewall_report](https://github.com/cumakurt/firewall_report)

---

## 👤 Developer

**Cuma Kurt**

- GitHub: [@cumakurt](https://github.com/cumakurt)
- LinkedIn: [Cuma Kurt](https://www.linkedin.com/in/cuma-kurt-34414917/)
- Repository: [https://github.com/cumakurt/firewall_report](https://github.com/cumakurt/firewall_report)

---

**Made with ❤️ for network administrators and security professionals**

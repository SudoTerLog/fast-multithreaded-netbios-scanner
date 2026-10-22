# Fast Multithreaded NetBIOS & Port Scanner

A production-ready, high-speed local network scanner built in Python. Designed to audit local subnets, bypass aggressive local firewalls, and extract actual computer names using asynchronous threads.

## 🚀 Key Features
- **High-Speed Multithreading:** Powered by `ThreadPoolExecutor` (50 workers) to scan /24 subnets in seconds.
- **Firewall Bypass:** Audits active Windows ports (445, 135, 139) to detect live hosts even if ICMP ping is blocked.
- **Deep Identification:** Extract computer names via raw UDP NetBIOS requests (Port 137), `nbtstat` parsing, and reverse DNS lookups.
- **Structured Output:** Automatically filters dead hosts and saves an ordered CSV report.

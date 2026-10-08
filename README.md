# Aegis
1. Install Python 3.10+ and Ollama; run `ollama list` and put a model you have in config.json ("ollama_model").
2. `pip install -r requirements.txt`
3. `python app.py`  ->  dashboard at http://127.0.0.1:8080/_aegis/ (localhost only)
Traps: /robots.txt, /api/v1/internal/config, /.git/config, /backup.sql.bak, /admin/login
Add your own IPs to "allowlist" in config.json so you aren't scored. Set webhook type (discord|slack|telegram) + url to get alerts.
Blocking commands are advisory text only; Aegis never changes your firewall.

## New in this version
- traps.txt: ~800 decoy paths by category (edit freely). Decoy identity is invented by Ollama on first run.
- Desktop app: `python aegis_desktop.py` (needs `pip install pywebview`) or run build_exe.bat to make dist\Aegis.exe.
- Multi-sensor: central PC sets "role":"central" + "sensor_key"; other machines set "role":"sensor", "central_url":"http://CENTRAL:8080", same "sensor_key".
- Dashboard passwords: set admin_password / viewer_password to allow remote logins (browser Basic Auth, use HTTPS in real use).
- Canarytokens: paste the AWS key into canary_key / canary_secret. AbuseIPDB: paste key into abuseipdb_key.

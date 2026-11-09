# Email auth (SPF/DKIM/DMARC) analyzer

**Author:** Md Shohrab Hossen Niaz

Parse DNS-like TXT export records and score email authentication posture for spoofing resistance.

```powershell
python -m src.cli analyse --path .\data\dns_txt_export.json
```

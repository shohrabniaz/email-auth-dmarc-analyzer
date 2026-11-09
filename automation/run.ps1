Set-Location (Split-Path -Parent $PSScriptRoot)
python -m src.cli analyse --path .\data\dns_txt_export.json
python tests\test_smoke.py

# Security Coverage Tracker MVP v0.2.1

Local-first security control coverage application for Windows and cross-platform development.

## Network defaults
- Listens on all LAN interfaces: `0.0.0.0`
- Default TCP port: `7777`
- Local URL: `http://127.0.0.1:7777`
- LAN URL: `http://<server-ip>:7777`

The host and port can be overridden without editing the source:

```powershell
$env:SCT_HOST="0.0.0.0"
$env:SCT_PORT="7777"
python run.py
```

## Run from source
```powershell
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python run.py
```

Default credentials: `admin` / `ChangeMe123!`

## Permit inbound LAN connections on Windows
Run PowerShell as Administrator:

```powershell
New-NetFirewallRule -DisplayName "Security Coverage Tracker TCP 7777" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 7777 -Profile Domain,Private
```

Alternatively, run `allow_firewall_port_7777.bat` as Administrator.

Find the server IPv4 address with:

```powershell
ipconfig
```

A LAN user can then open, for example:

```text
http://192.168.1.25:7777
```

## Security note
Port 7777 exposes the application to devices that can reach the host. Keep the Windows network profile set to **Private** or **Domain**, restrict the firewall rule to trusted subnets where possible, change the default administrator password, and place the application behind HTTPS before using it across untrusted networks.

## Control Sets module
Authorized users can add custom security controls, edit their metadata, activate or deactivate them, and initialize control status across existing assets.

## Existing v0.1.0 or v0.2.0 database
Keep the existing `data/security_coverage.db` file to preserve data. The application upgrades compatible schemas automatically.

## Build portable Windows executable
Run `build_windows.bat`. The output is created under `dist/`.

## CSV headers
Asset: `cmdb_id,hostname,fqdn,ip_address,operating_system,owner,business_unit,environment,criticality,lifecycle_status,notes`

Coverage: `hostname,status,agent_version,last_seen,source`

Coverage status values: `Protected`, `Missing`, `Unknown`, `Not Applicable`.

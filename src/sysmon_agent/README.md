# sysmon_agent

Reads events from the Windows `Microsoft-Windows-Sysmon/Operational` channel, redacts
common secret patterns in command-line fields, and POSTs batches to a configured HTTP
endpoint. Resumes across restarts via a record-id bookmark.

## Prerequisites

### 1. Sysmon

The agent reads the Sysmon event channel — Sysmon itself must be installed and running.

1. Download Sysmon from <https://learn.microsoft.com/sysinternals/downloads/sysmon>.
2. From an **elevated** PowerShell, install it with a config of your choice:
   ```powershell
   .\Sysmon64.exe -accepteula -i sysmonconfig.xml
   ```
   (Without a config, Sysmon logs almost nothing. SwiftOnSecurity's
   [`sysmonconfig-export.xml`](https://github.com/SwiftOnSecurity/sysmon-config)
   or Olaf Hartong's [`sysmon-modular`](https://github.com/olafhartong/sysmon-modular)
   are common starting points.)
3. Verify it's running:
   ```powershell
   Get-Service Sysmon64
   wevtutil get-log "Microsoft-Windows-Sysmon/Operational"
   ```

### 2. Rust toolchain (MSVC)

```powershell
rustup default stable-x86_64-pc-windows-msvc
```

### 3. Visual Studio Build Tools + Windows SDK

The MSVC Rust target links against `link.exe` and the Windows SDK libraries.

1. Install **Visual Studio** or **Build Tools for Visual Studio** from
   <https://visualstudio.microsoft.com/downloads/>.
2. In the Installer → **Modify** → **Workloads** tab → tick
   **"Desktop development with C++"**.
3. In the right panel, make sure a **Windows 10 SDK** or **Windows 11 SDK**
   component is checked.

## Configuration

### Required env var

```
SYSMON_AGENT_API_ENDPOINT=https://your-backend/api/v1/ingest
```

That's the only runtime setting. A `.env.example` ships in this directory.

### Everything else

All tunables — channel name, poll interval, batch size, flush interval, retry
policy, drop-list of event IDs, secret-redaction patterns — live in
[`src/config.rs`](src/config.rs) as `pub const`s. Edit and rebuild to change them.

## Build

From `src/sysmon_agent/`:

```powershell
cargo build --release
```

The binary is at `target/release/sysmon_agent.exe`. It is statically linked
(via `.cargo/config.toml` setting `+crt-static`) — drop it on any Windows host
and run; no Visual C++ redistributable required on the target.

> If `cargo` complains that `link.exe` can't be found, open
> **"Developer PowerShell for VS"** from the Start menu (it pre-sets `PATH`
> / `LIB` / `INCLUDE`) and rerun from there, or one-shot your current shell:
> ```powershell
> & "<vs-install>\Common7\Tools\Launch-VsDevShell.ps1" -Arch amd64 -HostArch amd64
> ```

## Run

The Sysmon channel is restricted — run the agent **as Administrator** or add
your account to the **Event Log Readers** group.

```powershell
$env:SYSMON_AGENT_API_ENDPOINT = "http://127.0.0.1:8080"
cargo run --release
# or
.\target\release\sysmon_agent.exe
```

Stop with `Ctrl+C` — the agent drains the in-flight batch and writes its
bookmark before exiting.

Bookmark location: `%PROGRAMDATA%\LOTL-Analyzer\sysmon_agent\bookmark`.

### Grant read access without running elevated

From an elevated shell, once:

```powershell
Add-LocalGroupMember -Group "Event Log Readers" -Member "$env:USERDOMAIN\$env:USERNAME"
```

Log out and back in so the group membership takes effect.

## Smoke test without a real backend

A throwaway HTTP listener to confirm batches are being shipped:

```powershell
@'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json, sys
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode("utf-8", "replace")
        try:    print(json.dumps(json.loads(body), indent=2)[:4000])
        except: print(body[:4000])
        sys.stdout.flush()
        self.send_response(200); self.end_headers()
ThreadingHTTPServer(("127.0.0.1", 8080), H).serve_forever()
'@ | Set-Content -Encoding utf8 echo_server.py

python echo_server.py
```

Point `SYSMON_AGENT_API_ENDPOINT` at `http://127.0.0.1:8080` and trigger some
Sysmon events (e.g. open `cmd.exe`, run `whoami`). Batches should appear.

## Running in the background

The agent is a plain console binary — it doesn't speak the Windows Service
Control Manager protocol. Two easy ways to keep it alive across logoff / reboot:

### Option A — NSSM (simplest)

[NSSM](https://nssm.cc) wraps any `.exe` as a real Windows service.

```powershell
nssm install SysmonAgent "E:\LOTL-Analyzer\src\sysmon_agent\target\release\sysmon_agent.exe"
nssm set SysmonAgent AppEnvironmentExtra SYSMON_AGENT_API_ENDPOINT=https://your-backend/...
nssm start SysmonAgent
```

### Option B — Task Scheduler

Create a task with:

- Trigger: **At system startup**
- Action: run `sysmon_agent.exe`, with `SYSMON_AGENT_API_ENDPOINT` set on the action's environment
- General: **Run whether user is logged on or not**, **Run with highest privileges**

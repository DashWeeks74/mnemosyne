# Mnemosyne — a local memory for Claude

This gives Claude a memory of decisions and reasoning you've discussed before — "what did we decide
about X" or "why did we choose Y" — that it can search back through instead of you having to
re-explain everything each time. It runs entirely on your own computer: no account, no API key, no
company sees your data, and after the one-time setup it works fully offline.

**Requires:** Claude Code (Anthropic's CLI/IDE tool) already installed and working on your machine.
This isn't a Claude Code install guide — get that running first, then come back to this.

## Install (5 minutes)

**First, download this repo:** go to
[github.com/DashWeeks74/mnemosyne](https://github.com/DashWeeks74/mnemosyne) → click the green
**Code** button → **Download ZIP**. It'll save as `mnemosyne-main.zip`, probably in your Downloads
folder.

### Windows

Start menu → type `PowerShell` → Enter → paste this (edit the first line if the zip isn't in
Downloads):

```powershell
$zip = "$env:USERPROFILE\Downloads\mnemosyne-main.zip"
$temp = "$env:TEMP\mnemosyne_extract"
Remove-Item -Recurse -Force $temp -ErrorAction SilentlyContinue
Expand-Archive -Path $zip -DestinationPath $temp -Force
New-Item -ItemType Directory -Force "$env:USERPROFILE\.mnemosyne" | Out-Null
Copy-Item -Recurse -Force "$temp\mnemosyne-main\*" "$env:USERPROFILE\.mnemosyne"
```

Then run the one-time setup (still in the same PowerShell window):

```powershell
& "$env:USERPROFILE\.mnemosyne\setup.ps1"
```

### Mac

Cmd+Space → type `Terminal` → Enter → paste this (edit the first line if the zip isn't in
Downloads):

```bash
zip=~/Downloads/mnemosyne-main.zip
temp=$(mktemp -d)
unzip -o "$zip" -d "$temp"
mkdir -p ~/.mnemosyne
cp -r "$temp/mnemosyne-main/." ~/.mnemosyne
```

Then run the one-time setup:

```bash
bash ~/.mnemosyne/setup.sh
```

**Either way**, the setup script installs a private copy of everything Mnemosyne needs — it doesn't
touch anything else on your computer. It'll print `Done!` when finished. If it can't find Python, it
tells you exactly what to install and where to get it — follow that, then run the setup command
again.

## Make Claude use it automatically (optional, but the whole point)

Without this step you'd have to run Mnemosyne by hand every time. With it, Claude reaches for it on
its own whenever it's relevant.

**Windows:**
```powershell
Copy-Item -Recurse -Force "$env:USERPROFILE\.mnemosyne\skill" "$env:USERPROFILE\.claude\skills\mnemosyne"
```

**Mac:**
```bash
mkdir -p ~/.claude/skills
cp -r ~/.mnemosyne/skill ~/.claude/skills/mnemosyne
```

Then **start a new Claude Code session** (or restart if one's already open) — skills are only picked
up when a session starts.

## Check it worked

Ask Claude: *"what skills do you have available?"* — `mnemosyne` should be in the list.

You can also test it directly yourself:
- Windows: `& "$env:USERPROFILE\.mnemosyne\mnemosyne.cmd" status`
- Mac: `~/.mnemosyne/mnemosyne.sh status`

It should print something like "files: 0, chunks: 0" — that's correct, nothing's been saved yet.

## How to use it

Just talk to Claude normally. Two things it'll do on its own once the skill is installed:

- **Ask it to remember something:** *"remember this decision"*, *"save this for later"*, *"add this
  document to memory"* — point it at a note, a document, or just describe what to remember.
- **Ask about the past:** *"what did we decide about the database?"*, *"why did we go with that
  approach?"* — it searches everything you've had it remember and shows you the actual source, not
  just an answer it made up. Every result names exactly where it came from.

The first time it actually needs to think about meaning (not just match words), it'll quietly
download a small AI model (about 130MB, one time, needs internet for that one moment) — after that,
everything is fully offline.

## If something seems off

- **Claude didn't use it, just answered normally** — say "use the mnemosyne skill" once; it should
  pick up on similar requests after that.
- **A query comes back empty** — ask Claude to run `mnemosyne.cmd status` (or `mnemosyne.sh status`)
  to check whether anything's actually been saved yet.
- **Setup failed partway through** — safe to just run the setup script again from the start.

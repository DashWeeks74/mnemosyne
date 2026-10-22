# Mnemosyne — a local memory for Claude

This gives Claude a memory of decisions and reasoning you've discussed before — "what did we decide
about X" or "why did we choose Y" — that it can search back through instead of you having to
re-explain everything each time. It runs entirely on your own computer: no account, no API key, and
nothing you save is ever sent to any company or service — the search itself is a local computation,
not a call to anyone's API. (More on exactly what that means, including one small one-time download,
further down.)

**Requires:** Claude Code (Anthropic's CLI/IDE tool) already installed and working on your machine.
This isn't a Claude Code install guide — get that running first, then come back to this.

## Why "Mnemosyne"?

In Greek mythology, Mnemosyne is the Titaness who personifies memory itself — and the mother of the
nine Muses, who preside over every art and science that grew out of what she remembered. It's about
as literal a name as you can get for a tool whose only job is remembering things accurately and
handing them back, unchanged, when asked.

## Why not just use Claude's built-in memory?

Claude Code already has its own memory feature, so this is a fair question. They do different jobs,
and you can use both:

- **Built-in memory is Claude's own notes, in its own words.** It writes short summaries of things it
  decided were worth remembering. Handy, but a summary can drift from what you actually said or wrote
  — and there's no way to check that later, because the original isn't kept alongside it.
- **Mnemosyne remembers the source, not a summary of it.** Every answer comes back as a citation —
  the actual document, the exact spot in it, when it was saved — and it flags if that file has
  changed since. You can always go check the real thing instead of trusting a paraphrase.
- **Built-in memory is curated by Claude** — it decides what's worth saving. Mnemosyne remembers
  whatever you point it at: a whole report, a full set of notes, not just what an AI judged
  interesting enough to write down.
- **Secret safety is a technical check here, not a promise.** Mnemosyne scans and redacts anything
  password- or key-shaped before it's ever stored. That's an actual scan running on the content, not
  an instruction Claude is just trusting itself to follow.
- **This isn't tied to any one product.** Built-in memory is a Claude Code feature. Mnemosyne is a
  small standalone tool that happens to work well with it — it'll still be exactly what it is even if
  that feature changes.

Rule of thumb: built-in memory is great as Claude's running notes on you. Mnemosyne is for "I know I
wrote this down somewhere — find it, and prove it's actually what I wrote."

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
- **Capture a small decision:** *"capture that"*, *"file this decision"* — Claude writes a short note
  (a "capture", see below) and saves it, with links to related decisions.
- **Catch up at the start of a session:** *"what's still open?"* — Claude lists the open captures and
  the ones you touched most recently.

The first time it needs to compare *meaning* rather than just matching words, it downloads a small
(~130MB) model to do that — **not Claude, not an agent, nothing that "thinks" or generates text.** It's
a much simpler kind of model whose only job is turning a piece of text into a list of numbers that
represent what it means, so "why did we pick Postgres" can match a document that says "we chose
Postgres because..." even though the wording is different — pure math on those numbers, nothing more.
That download needs internet, once; every comparison after that runs locally, no internet involved.

**What "runs locally" actually promises, precisely:** Mnemosyne's own search and storage never call
out to any company's API and never send your data anywhere — that's the real guarantee, and it holds
regardless of how much internet you have. It is *not* a claim that your whole Claude Code setup can
run with no internet at all — Claude Code itself always needs a connection to reach Anthropic.
Mnemosyne just doesn't add a second company, a second API key, or a second point of failure on top of
that.

## Captures: small decisions that link to each other

Not every decision deserves a whole document. A **capture** is one tiny markdown file — a few lines at
the top saying what was decided — that can point at other captures or documents. Only three fields are
required:

```markdown
---
kind: capture
id: ups-alert-routing
what: Route UPS power alerts through Telegram
status: open
applies_to:
  - alert-routing: like
  - telegram-bot-setup: depends-on
  - ../docs/network-plan.md#Alerting: supersedes
---
```

The optional fields are `date`, `outcome`, `status` (`filed`, `open`, `done` or `superseded`) and
`applies_to`, a list of links. Each link names its relation: `like`, `depends-on`, `blocked-by`,
`supersedes`, `contradicts` or `applies-to` (the default). Keep captures in a folder of their own and
ingest that folder like any other. When a search hits a capture, the result also shows what it links
to and what links to it, one step out in each direction. A capture that doesn't parse is still stored
as ordinary text; ingest prints a `CAPTURE-INVALID` warning and records no links for it, so nothing is
lost and the problem is visible.

## Running it by hand

Claude runs these for you, but they're plain commands (Windows shown; on Mac use `mnemosyne.sh`):

```text
mnemosyne.cmd ingest "<file or folder>" --project NAME   save something (safe to re-run)
mnemosyne.cmd query "why did we pick Postgres?"          search; every hit is a citation
mnemosyne.cmd recent                                     open captures + most recently touched
mnemosyne.cmd status                                     what's saved, and anything wrong with it
mnemosyne.cmd flag-last "it found the wrong doc"         mark the last search as a bad result
mnemosyne.cmd forget --path "<file>"                     remove one file's entries
mnemosyne.cmd forget --project NAME                      PREVIEW a whole-project delete (deletes nothing)
```

- **`--json`** on `query`, `recent` and `status` prints one machine-readable document instead of text.
- **Deleting a whole project takes two steps on purpose.** `forget --project NAME` on its own only
  shows what would go and deletes nothing. To really delete, run it again with
  `--expect-chunks N`, using the number the preview printed. If the number doesn't match (say,
  something was added since), it refuses.
- **Exit codes** are meant for scripts: 0 done, 1 nothing done, 2 refused, 3 refused a lexical-only
  ingest (the private environment is broken; re-run setup), 4 finished but something wasn't fully
  saved, 5 forget preview only, 97 the launcher found a broken install.
- On Windows, put every argument in double quotes, and avoid `"`, `%` or `^` inside an argument or a
  trailing backslash — `cmd.exe` re-reads the line and can misinterpret them. `mnemosyne.sh` doesn't
  have this problem.

## What it refuses to store

The secret scan has several layers, because one regex list is never enough:

- **Credential-named files are skipped** (`.env`, `credentials.json`, `id_rsa`, `*.pem`, anything
  under `.ssh`, and so on).
- **Secret-shaped values are redacted in place** — API keys, tokens, passwords — so the surrounding
  reasoning is still searchable but the value is never stored. The patterns live in
  `hooks/secret-rules.txt`; if that file is missing or has a rule Python can't read, `ingest` refuses
  to run at all rather than store something it couldn't check.
- **A file holding a private key is dropped whole**, since a key's body spans lines.
- **UTF-16 files are held to a stricter line.** Windows tools (PowerShell 5.1's `>`, Notepad's
  "Unicode") write UTF-16, which hides text from ordinary scanners. A UTF-16/32 or NUL-bearing file
  holding *any* secret-shaped value is dropped whole, and one over 4 MB isn't indexed at all. To save
  such a file, convert it to UTF-8 and take the secret out.
- **Scan versions.** Every file remembers which version of the scan indexed it. When the scan gets
  better (a Mnemosyne update, or you edit `hooks/secret-rules.txt`), `status` says which projects
  were "indexed by an OLDER secret scan"; re-ingest them and each file is re-checked once.
- **`.claude` folders are never indexed**, from any starting point, and there's no override.
  Mnemosyne also refuses to put its own database or logs inside one.

This is a strong filter, not a promise. Don't ingest something just to find out whether it's safe.

## Protecting a folder (optional)

If some folder on your machine must never be indexed — a live production system, say — list it in
`hooks/governed-roots.txt` inside the Mnemosyne folder. Copy `hooks/governed-roots.txt.example` to
start; it explains the format. A listed folder is refused by `ingest` (unless you pass
`--allow-governed` on purpose), and Mnemosyne will never write its own files into it. It's matched by
file identity as well as by name, so a shortcut, junction or alternate spelling that leads there is
caught too. With no such file, nothing is governed, which is the normal setup. (This release reads
Windows paths only; on Mac/Linux the file currently protects nothing.)

## Where it keeps things

Everything stays inside the Mnemosyne folder unless you say otherwise: the database
(`mnemosyne.db`), a `logs` folder (search log, bad-result flags, a `mnemosyne-status.json` snapshot)
and `watch-projects.txt` (projects you've marked high-stakes with `ingest --watch`). Set
`MNEMOSYNE_DB` to keep the database somewhere else; the logs and watch list then move next to it.
`MNEMOSYNE_LOG_DIR` moves just the logs. Mnemosyne checks every one of these locations before it
writes anything, and refuses to start if one is unsafe.

## Installing somewhere other than your home folder

The steps above put Mnemosyne at `%USERPROFILE%\.mnemosyne` / `~/.mnemosyne` and make it available to
*every* Claude Code project on your machine. That's just the easy default — nothing requires that
exact spot. Two real reasons to put it elsewhere:

**You want it scoped to one project, not your whole machine** — say, a separate memory per project
instead of one shared one. Put the whole `mnemosyne` folder inside that project instead of your home
folder, and install the skill into that project's own `.claude\skills\` instead of the global one:

```powershell
# Inside the project folder itself:
Copy-Item -Recurse -Force "$env:USERPROFILE\.mnemosyne" ".\mnemosyne"
New-Item -ItemType Directory -Force ".claude\skills" | Out-Null
Copy-Item -Recurse -Force ".\mnemosyne\skill" ".claude\skills\mnemosyne"
```

Then open `.claude\skills\mnemosyne\SKILL.md` and replace the `%USERPROFILE%\.mnemosyne\mnemosyne.cmd`
paths with just `mnemosyne\mnemosyne.cmd` (no drive letter, no `%USERPROFILE%`) — since Claude Code
runs commands from the project's own folder, a path relative to the project root is enough; it
doesn't need to be absolute. (Mac/Linux: same idea, `mnemosyne/mnemosyne.sh` in `SKILL.md`, and prefer
the `.sh` launcher over `.cmd` if the project path ever has a space in it — Git Bash can mis-split
quoted arguments against a `.cmd` target when that happens.)

**Claude Code itself is pointed at a different config root** — if you've set a custom
`CLAUDE_CONFIG_DIR` environment variable (an isolated Claude Code setup, separate from the normal
`~/.claude`), the *global* skills folder is `$CLAUDE_CONFIG_DIR\skills\` instead of
`~/.claude/skills/`. Same install commands, just swap that one destination folder — and in that case
an absolute path in `SKILL.md` (wherever you actually put the `mnemosyne` folder) works fine, since a
custom config root isn't tied to any one project's working directory the way the project-scoped case
above is.

Either way, the rule is the same: **the tool folder and the paths inside `SKILL.md` have to agree.**
If a query ever fails with "file not found," that's almost always the fix — check what `SKILL.md`
actually points at against where the `mnemosyne` folder actually is.

## If something seems off

- **Claude didn't use it, just answered normally** — say "use the mnemosyne skill" once; it should
  pick up on similar requests after that.
- **A query comes back empty** — ask Claude to run `mnemosyne.cmd status` (or `mnemosyne.sh status`)
  to check whether anything's actually been saved yet.
- **Setup failed partway through** — safe to just run the setup script again from the start.

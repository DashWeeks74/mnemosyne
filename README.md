# Mnemosyne — a local memory for Claude

This gives Claude a memory of decisions and reasoning you've discussed before — "what did we decide
about X" or "why did we choose Y" — that it can search back through instead of you having to
re-explain everything each time. It runs entirely on your own computer: no account, no API key, and
nothing you save is ever sent to any company or service — the search itself is a local computation,
not a call to anyone's API. (More on exactly what that means, including one small one-time download,
further down.)

**Requires:** Claude Code (Anthropic's CLI/IDE tool) already installed and working on your machine.
This isn't a Claude Code install guide — get that running first, then come back to this.

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

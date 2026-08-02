---
name: mnemosyne
description: Local, offline memory of past decisions and reasoning - not code search, not file search, but "why did we decide X" / "what did we conclude about Y" over things previously written down. Use when the user asks a natural-language question about a past decision, rationale, conclusion, or "why did we..." that isn't answerable by just reading current files or code - query Mnemosyne first before falling back to manual search. Also use when the user asks to remember, save, or ingest a document, note, or decision for later recall. Triggers on "what did we decide about", "why did we choose", "what was the reasoning behind", "remember this", "add this to memory", "have we talked about this before", or "mnemosyne".
---

# Mnemosyne - local decision memory

A local, offline tool that remembers *decisions and reasoning* (not code, not files - use normal
file search for those). Everything it knows came from documents the user explicitly asked to be
"ingested" - it never sees anything else, and it runs entirely on this computer with no account,
no API key, no internet needed after first setup.

**Where it lives (fixed location, same on every machine it's installed on):**
- Windows: `%USERPROFILE%\.mnemosyne\mnemosyne.cmd`
- Mac/Linux: `~/.mnemosyne/mnemosyne.sh`

If that file doesn't exist, Mnemosyne isn't installed yet - don't guess at another path, tell the
user and stop.

## When to query it

Before answering a question like "what did we decide about X", "why did we go with Y instead of Z",
or "what was the plan for W" - if the answer isn't obvious from files already open or already read
in this conversation, query Mnemosyne first:

```
%USERPROFILE%\.mnemosyne\mnemosyne.cmd query "the user's question, in plain words"
```
(or the `.sh` equivalent on Mac/Linux)

Every result is a **citation, not an answer** - it returns the matching text plus exactly where it
came from and when. Read the source before treating it as settled fact if the answer matters; say so
plainly if nothing relevant comes back rather than guessing.

## When to ingest something

If the user says something like "remember this", "save this decision", "add this to memory", or
hands over a document/note they want recalled later:

```
%USERPROFILE%\.mnemosyne\mnemosyne.cmd ingest "<path to the file or folder>" --project <short-name>
```

Pick `--project` as a short, sensible label for whatever this belongs to (a project name, a topic).
Ingesting is safe to re-run - unchanged files are skipped automatically. It only reads markdown/text
files (`.md`, `.txt`, etc.) and automatically skips anything that looks like a password, API key, or
credential file - it will never store a secret, by design.

## Checking what it knows

```
%USERPROFILE%\.mnemosyne\mnemosyne.cmd status
```

Shows how much has been ingested and from where. Useful if a query comes back empty and the user
wants to know whether something was ever actually saved.

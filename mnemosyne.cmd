@echo off
REM mnemosyne.cmd - Windows launcher. Self-contained: does not change your current folder,
REM so relative paths you pass (e.g. "ingest .") resolve against wherever YOU are, not this folder.
REM Runs this install's own .venv (made by setup.ps1) and this folder's mnemosyne.py, by absolute path,
REM so a stray mnemosyne.py in your current folder is never run instead.
REM
REM Exit codes are passed through unchanged (a refusal is never reported as success):
REM   0 ok, 1 nothing done / warning, 2 refused, 3 lexical-only ingest refused, 4 ingest had failed
REM   files, 5 forget --project preview (nothing deleted), 97 this launcher found a broken install.
REM An inherited ERRORLEVEL environment variable would shadow the real exit code, so it is cleared.
REM
REM CALLER RULE (cmd re-parses the argument line; batch cannot prevent this): wrap every argument in
REM double quotes; no argument may contain " or % or ^ or a line break, and none may END in a
REM backslash (python would merge it with the next argument). mnemosyne.sh has no such limits.
setlocal
set "ERRORLEVEL="
REM (The messages below deliberately do not echo the folder path: a ")" in it would end the block.)
if not exist "%~dp0.venv\Scripts\python.exe" (
    echo mnemosyne: no .venv in the Mnemosyne folder - run setup.ps1 there first. 1>&2
    exit /b 97
)
if not exist "%~dp0mnemosyne.py" (
    echo mnemosyne: mnemosyne.py is missing from the Mnemosyne folder - re-copy the install. 1>&2
    exit /b 97
)
"%~dp0.venv\Scripts\python.exe" "%~dp0mnemosyne.py" %*
exit /b %ERRORLEVEL%

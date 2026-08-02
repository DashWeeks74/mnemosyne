@echo off
REM mnemosyne.cmd - Windows launcher. Self-contained: does not change your current folder,
REM so relative paths you pass (e.g. "ingest .") resolve against wherever YOU are, not this folder.
"%~dp0.venv\Scripts\python.exe" "%~dp0mnemosyne.py" %*

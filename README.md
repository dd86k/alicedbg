# alicedbg, a debugger

alicedbg aims to be a simple debugger.

This exists because I wanted an easy-to-use debugger with an non-interactive
mode (catch, print, exit) and and interactive mode (for lengthy sessions)
available anywhere and anytime, even via SSH.

# Usage

## Getting started

To debug an application, use -file FilePath, or to debug an existing process, use -pid ProcessID.

To specify a UI, use the -ui option. Currently, there is only `tui` and `loop`. Default is `tui`.
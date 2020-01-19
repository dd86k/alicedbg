# alicedbg, a debugger

alicedbg aims to be a simple debugger.

**Please note that this is still is very early development!**

It exists because I wanted an easy-to-use debugger with multiple
user-interfaces available anywhere and anytime, even via SSH.

More details to come.

# Usage

## Getting started

To debug an application, use -exec PATH, or to debug an existing process,
use -pid PROCESSID.

### User Interfaces

An user interface can be specified with the `-ui` option.

`-ui ?` outputs this list:

| UI | Description |
|---|---|
| `tui` (Default) | (WIP) Text UI |
| `loop` | Simple catch-try loop with no user input |
| `tcp-json` | (Planned feature) TCP+JSON API server |

#### UI: tui

The tui UI is currently in development.

#### UI: loop

The loop UI is the simplest implementation, featuring simple output on
exceptions. The UI continues automatically on exceptions and is not
interactive.

On exceptions, this is added to output:
```
* EXCEPTION #0
PID=4104  TID=2176
BREAKPOINT (80000003) at 77ABF146
Code: CC  (INT 3)
```

Which features the exception counter, process ID, thread ID (Windows-only),
exception messsage (with its OS-specific code), memory location, and a
brief disassembly (when available).
# Poppy

A small menu bar app that keeps an eye on memory on an 8 GB Mac and tells you what to quit before it starts thrashing.

- **Menu bar:** chip icon + memory in use (100 − the kernel's "available %"). Turns orange on *warning*, red on *critical*.
- **Could quit:** ranked suggestions. Apps are ranked by size, growth over the last ~10 min, and how long since you last used them (the app you're in gets a big discount). Command-line tools are suggested one process at a time, with what they're running and where (`node · vite · in ~/…/lattice`).
- **Growing:** anything that has gained more than 150 MB in the last 10 minutes (handy for spotting leaks).
- **Everything:** all your processes, grouped by app. Each app has a submenu: Quit, ⌥ Force quit, and a list of its processes; click one to stop it (SIGTERM), or hold ⌥ and click to force-kill it (SIGKILL).
- **Notifications** when pressure rises, with a "Quit X" button for the top suggestion. These repeat every 5 min while critical, every 15 while warning.
- **Log** at `~/Library/Logs/Poppy.log`: a snapshot of the top memory users on every pressure change, and every 5 min while under pressure. After a freeze, look here to see what happened.
- Never touches Finder, Dock, loginwindow, WindowServer and the like. System processes are listed but not suggested (they usually just respawn).

It only sees your own processes. Root daemons (`kernel_task`, `WindowServer`, `mds_stores`…) can't be read or killed without sudo, but their memory is still included in the wired/compressed totals.

## Build / install

    ./build.sh             # builds Poppy.app here
    ./build.sh --install   # copies to ~/Applications and launches; registers as a login item on first run

    Poppy.app/Contents/MacOS/Poppy --report      # same analysis, printed in the terminal
    Poppy.app/Contents/MacOS/Poppy --report -v   # ...with per-process breakdown

    POPPY_SIMULATE=critical Poppy.app/Contents/MacOS/Poppy   # try out the alerts

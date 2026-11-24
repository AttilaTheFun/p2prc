# End-to-end checks

The web client and the Android app, driven the way a person would, on two
devices that pair, message and reopen.

- `run_pair.sh`: two iOS simulators open the web build in Safari
  (`CONVO_E2E_RELAY=1`: their peer link through the nodes' TURN alone, the
  candidate pair in the log). A creates
  an identity and shows a pairing code, and B opens the invite. They exchange a
  message each way. A goes back to the inbox and reopens the thread, then a
  probe records the keyboard layout. It logs to `out/pair.log` and writes
  screenshots to `out/`.
- `run_android_thread.sh`: one simulator runs the web side. The Android
  emulator joins through the invite, opens the thread at its end and
  receives messages while it's open. It logs to `out/emu/thread.log`, with
  screenshots beside it.
- `driver.js` is injected into the served site. It taps by text or
  accessibility label, presses the switch, types, sends, and beacons the
  page's text, errors and fetch replies.
- `cmdserver.py` serves the site and relays commands to the driver and its
  beacons back to the log, on 127.0.0.1:8765.

Simulators: `CONVO_E2E_SIM_A` and `CONVO_E2E_SIM_B` (UDIDs), erased each run.
The emulator is its own AVD under `~/.cache/convo_emulator`, on port 5584.

**Where they run.** Both scripts build with Bazel and boot simulators and an
emulator on the machine they run on: a Mac with Xcode (CI runs `run_pair.sh`
on a macOS runner for each release's proof).

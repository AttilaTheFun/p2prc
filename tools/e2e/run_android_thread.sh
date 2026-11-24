#!/bin/bash
# Web simulator A shows a pairing code; the Android emulator opens the invite,
# onboards and joins; A sends enough messages to overflow the screen; the
# emulator opens the thread (should land at its end), then A sends more while
# it is open (should stay at the end). Screenshots in emu/.
set -u
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd); E=$HERE/out; mkdir -p "$E"; O=$E/emu; mkdir -p "$O"
# The web side runs in one iOS simulator: CONVO_E2E_SIM_A.
A=${CONVO_E2E_SIM_A:-7FCDAC0F-C4C3-4EA6-8554-B3787574679F}
mkdir -p $O; rm -f $O/t_*.png $O/thread.log
log(){ echo "$(date +%T) $*" >> $O/thread.log; }
cmd(){ echo "$2" >> $E/cmds.txt.$1; }
lastof(){ grep "\"who\": *\"$1\"" $E/weblog.txt 2>/dev/null | grep "$2" | tail -1 | sed -E 's/.*"m": *"//; s/"}$//'; }
waitfor(){ for i in $(seq 1 $3); do sleep 1; lastof $1 'text:' | grep -qE "$2" && return 0; done; log "$1 timed out waiting for: $2"; return 1; }
cd "$ROOT"
ADB="$(bazel info output_base)/external/isomer++android_tools+android_platform_tools/adb"

W=$(bazel cquery --output=files //applications/p2prc_web 2>/dev/null | head -1)
rm -rf $E/site && cp -R "$ROOT/$W" $E/site && chmod -R u+w $E/site && cp $HERE/driver.js $E/site/
python3 -c "
p='$E/site/index.html'; s=open(p).read(); open(p,'w').write(s.replace('<head>','<head><script src=\"/driver.js\"></script>',1))"
pkill -f cmdserver.py; rm -f $E/cmds.txt.* $E/weblog.txt; (cd $E/site && nohup python3 $HERE/cmdserver.py 8765 $E/weblog.txt $E/cmds.txt >/dev/null 2>&1 &)
# Our own emulator on our own port (5584), read-only so it never locks the
# shared AVD; every adb call names emulator-5584 and nothing else.
"${ADB:-$A}" devices | grep -q "^emulator-5584" && { echo "emulator-5584 already running; not touching it"; exit 1; }
# Its own AVD (the tool keeps state under $TMPDIR): another agent's emulator on
# the shared AVD, started without -read-only, would otherwise block this one.
mkdir -p $HOME/.cache/convo_emulator
(TMPDIR=$HOME/.cache/convo_emulator bazel run @isomer//tools/android/emulator -- -no-window -port 5584 -read-only > /tmp/emu.log 2>&1 &)
xcrun simctl shutdown $A >/dev/null 2>&1; xcrun simctl erase $A; xcrun simctl boot $A; xcrun simctl bootstatus $A -b >/dev/null 2>&1
for t in 1 2 3 4; do xcrun simctl openurl $A "http://127.0.0.1:8765/index.html?who=a" >/dev/null 2>&1; for i in $(seq 1 30); do sleep 2; grep -q '"who":"a","t":[0-9]*,"m":"text: .' $E/weblog.txt 2>/dev/null && break 2; done; done
waitfor a 'Create a new identity' 60; cmd a 'text:Create a new identity'; waitfor a 'Your recovery phrase' 30; sleep 2
cmd a 'toggle'; sleep 2; cmd a 'text:Continue'; waitfor a 'Inbox|No conversations' 60
for try in 1 2 3 4; do cmd a 'aria:New Conversation'; waitfor a 'Show a Pairing Code' 8 && break; done
cmd a 'text:Show a Pairing Code'; waitfor a 'Scan the code|have them scan' 60; sleep 2; cmd a 'hash'; sleep 3
H=$(lastof a 'hash #c=' | sed 's/.*hash //'); log "invite ${H:0:24}"
S=emulator-5584; for i in $(seq 1 90); do [ "$("$ADB" -s $S shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && break; sleep 4; done; [ "$("$ADB" -s $S shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] || { log "emulator $S never booted: $(tail -1 /tmp/emu.log)"; pkill -f cmdserver.py; xcrun simctl shutdown $A; exit 1; }; log "emulator $S"
"$ADB" -s $S install -r bazel-out/darwin_arm64-opt/bin/applications/p2prc_android/p2prc_android_apk.apk >/dev/null
"$ADB" -s $S shell pm clear com.loganshire.p2prc >/dev/null
"$ADB" -s $S shell am start -n com.loganshire.p2prc/.MainActivity -a android.intent.action.VIEW -d "https://p2prc.org/$H" >/dev/null
tap(){ for i in $(seq 1 25); do "$ADB" -s $S shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; B=$("$ADB" -s $S shell cat /sdcard/ui.xml | tr '>' '\n' | grep -E "(text|content-desc)=\"$1\"" | grep -oE 'bounds="[^"]*"' | head -1); [ -n "$B" ] && break; sleep 1; done; [ -z "$B" ] && { log "missing: $1"; return 1; }; read x1 y1 x2 y2 <<< $(echo "$B" | grep -oE '[0-9]+' | tr '\n' ' '); "$ADB" -s $S shell input tap $(( (x1+x2)/2 )) $(( (y1+y2)/2 )); log "tapped: $1"; }
# A Toggle's label doesn't flip it (and a disabled Continue no longer runs):
# tap the checkable node itself.
tapswitch(){ for i in $(seq 1 25); do "$ADB" -s $S shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; B=$("$ADB" -s $S shell cat /sdcard/ui.xml | tr '>' '\n' | grep 'checkable="true"' | grep -oE 'bounds="[^"]*"' | head -1); [ -n "$B" ] && break; sleep 1; done; [ -z "$B" ] && { log "missing: switch"; return 1; }; read x1 y1 x2 y2 <<< $(echo "$B" | grep -oE '[0-9]+' | tr '\n' ' '); "$ADB" -s $S shell input tap $(( (x1+x2)/2 )) $(( (y1+y2)/2 )); log "tapped: switch"; }
shot(){ sleep 3; "$ADB" -s $S exec-out screencap -p > $O/$1.png; }
tap "Create a new identity"; tapswitch; sleep 1; tap "Continue"
sleep 40; shot t_1_after_join; tap "Skip" || true
waitfor a 'Skip|peer-' 90; cmd a 'text:Skip'; waitfor a 'peer-' 30
for try in 1 2 3; do cmd a 'row'; waitfor a 'Say something|Message' 8 && break; done
for n in $(seq 1 14); do cmd a "type:message number $n from the web"; sleep 1; cmd a 'send'; sleep 2; done
sleep 20; shot t_2_inbox
"$ADB" -s $S shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; R=$("$ADB" -s $S shell cat /sdcard/ui.xml | tr '>' '\n' | grep -E 'text="peer-' | grep -oE 'bounds="[^"]*"' | head -1)
[ -z "$R" ] && { log "no conversation row on screen; stopping"; "$ADB" -s $S emu kill >/dev/null 2>&1; exit 1; }
read x1 y1 x2 y2 <<< $(echo "$R" | grep -oE '[0-9]+' | tr '\n' ' '); "$ADB" -s $S shell input tap $(( (x1+x2)/2 )) $(( (y1+y2)/2 )); log "opened thread"
shot t_3_thread_open
for n in $(seq 15 18); do cmd a "type:message number $n arrives while open"; sleep 1; cmd a 'send'; sleep 3; done
sleep 15; shot t_4_after_new
"$ADB" -s $S shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; log "visible: $("$ADB" -s $S shell cat /sdcard/ui.xml | tr '>' '\n' | grep -oE 'text="message number [0-9]+[^"]*"' | tr '\n' ' ')"
log "fatal: $("$ADB" -s $S logcat -d | grep -c 'FATAL EXCEPTION')"
"$ADB" -s $S emu kill >/dev/null 2>&1; pkill -f cmdserver.py; xcrun simctl shutdown $A >/dev/null 2>&1; sleep 4
"${ADB:-$A}" devices | grep -q "^emulator-5584" && log "emulator still running" || log "emulator stopped"; log done

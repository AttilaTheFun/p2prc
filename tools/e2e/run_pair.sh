#!/bin/bash
# Two simulators: A creates an identity and shows a pairing code, B opens the
# invite link, they pair, each sends a message, each must see both; then A
# goes back to the inbox and into the thread again (onDisappear / task cancel).
set -u
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd); E=$HERE/out; mkdir -p "$E"
# Two iOS simulators by UDID (pairing needs two): set CONVO_E2E_SIM_A/B.
# CONVO_E2E_RELAY=1: the peer link through the nodes' TURN alone
# (driver.js's relay=1), its candidate pair in the log.
R=""; [ "${CONVO_E2E_RELAY:-}" = 1 ] && R="&relay=1"
A=${CONVO_E2E_SIM_A:-7FCDAC0F-C4C3-4EA6-8554-B3787574679F}; B=${CONVO_E2E_SIM_B:-8339C995-35E0-4AD8-9BEB-3311236D6958}
log(){ echo "$(date +%T) $*" >> $E/pair.log; }
cmd(){ echo "$2" >> $E/cmds.txt.$1; }
# waitfor who pattern seconds: until that side's latest screen text matches.
waitfor(){ for i in $(seq 1 $3); do sleep 1; lastof $1 'text:' | grep -qE "$2" && return 0; done; log "$1 timed out waiting for: $2"; return 1; }
lastof(){ grep "\"who\": *\"$1\"" $E/weblog.txt 2>/dev/null | grep "$2" | tail -1 | sed -E 's/.*"m": *"//; s/"}$//'; }
openwait(){ for t in 1 2 3 4; do xcrun simctl openurl $1 "$2" >/dev/null 2>&1; for i in $(seq 1 30); do sleep 2; grep -q "\"who\": *\"$3\",\"t\":[0-9]*,\"m\":\"text: ." $E/weblog.txt 2>/dev/null && return 0; done; log "$3 not loaded yet, reopening"; done; return 1; }
# Onboard after the recovery phrase: the switch, then Continue, retried until
# the inbox shows (a cold first load can still be drawing when Continue is
# pressed); a retry is logged with the switch's state.
# Create the identity: the tap retried until the recovery phrase shows (a
# first page can still be drawing when the tap lands, and nothing comes of it).
# Onboarding creates it again when it finds the first page back (Safari can
# reload a tab in the simulator, losing the identity not yet saved).
create(){ waitfor $1 'Create a new identity' 60; for t in 1 2 3 4; do cmd $1 'text:Create a new identity'; waitfor $1 'Your recovery phrase' 15 && return 0; log "$1 create retry $t"; done; return 1; }
# Back into the conversation, if the page has gone to the inbox (it reloads at
# times and starts there): its row tapped until the thread is drawn.
inthread(){ for t in 1 2 3; do lastof $1 'text:' | grep -q '^text: peer-' && return 0; log "$1 at the inbox: opening the conversation again"; cmd $1 'row'; waitfor $1 '^text: peer-' 8 && return 0; done; return 1; }
onboard(){ for t in 1 2 3 4; do if lastof $1 'text:' | grep -q 'Create a new identity'; then log "$1 back at the start (the page reloaded): creating again"; create $1; sleep 2; fi; cmd $1 'toggled'; sleep 2; lastof $1 '"m":"toggled ' | grep -q 'toggled true' || cmd $1 'toggle'; sleep 2; cmd $1 'text:Continue'; waitfor $1 "$2" 20 && return 0; log "$1 onboarding retry $t (switch: $(lastof $1 '"m":"toggled ' | sed 's/.*toggled //'))"; done; return 1; }
# The built site, by the execution root (CI's Bazel makes no bazel-out link in the checkout).
W=$(cd "$ROOT" && echo "$(bazel info execution_root 2>/dev/null)/$(bazel cquery --output=files //applications/p2prc_web 2>/dev/null | head -1)")
rm -rf $E/site && cp -R "$W" $E/site && chmod -R u+w $E/site && cp $HERE/driver.js $E/site/
python3 -c "
p='$E/site/index.html'; s=open(p).read(); open(p,'w').write(s.replace('<head>','<head><script src=\"/driver.js\"></script>',1))"
pkill -f cmdserver.py; rm -f $E/cmds.txt.* $E/weblog.txt $E/pair.log; (cd $E/site && nohup python3 $HERE/cmdserver.py 8765 $E/weblog.txt $E/cmds.txt >/dev/null 2>&1 &)
# Each simulator erased and booted under a time limit, and booted once more
# if it isn't up in 5 minutes: a boot that fails leaves `bootstatus -b`
# waiting for ever (a release's proof hung there until the job's timeout).
limit(){ perl -e 'alarm shift; exec @ARGV' "$@"; }
up(){ limit 300 xcrun simctl bootstatus $1 -b >/dev/null 2>&1; }
for D in $A $B; do
  log "${D:0:8} erasing and booting"; echo "run_pair: ${D:0:8} erasing and booting" >&2
  limit 60 xcrun simctl shutdown $D >/dev/null 2>&1; limit 180 xcrun simctl erase $D; limit 120 xcrun simctl boot $D
done
for D in $A $B; do
  up $D && continue
  log "${D:0:8} not up after 5 minutes: booting it again"; echo "run_pair: ${D:0:8} not up, booting again" >&2
  limit 60 xcrun simctl shutdown $D >/dev/null 2>&1; limit 120 xcrun simctl boot $D; up $D || { log "${D:0:8} did not boot"; exit 1; }
done
log "sims up"; echo "run_pair: sims up" >&2
openwait $A "http://127.0.0.1:8765/index.html?who=a$R" a
create a; sleep 2; onboard a 'Inbox|No conversations'
waitfor a 'Inbox|No conversations' 60
# The pairing code: New Conversation, then Show a Pairing Code, each tapped
# again until its screen shows (a tap can land before the view takes it).
for code in 1 2 3; do
  for try in 1 2 3 4; do lastof a 'text:' | grep -q 'Show a Pairing Code' && break; cmd a 'aria:New Conversation'; waitfor a 'Show a Pairing Code' 8 && break; done
  cmd a 'text:Show a Pairing Code'; waitfor a 'Scan the code|have them scan' 30 && break; log "a pairing code retry $code: $(lastof a 'text:' | cut -c1-80)"
done
sleep 2; cmd a 'hash'; sleep 3
H=$(lastof a 'hash #c=' | sed 's/.*hash //'); log "invite ${H:0:30}"
openwait $B "http://127.0.0.1:8765/index.html?who=b$R$H" b
create b; sleep 2; onboard b 'Skip|peer-|Pair|Name'
waitfor b 'Skip|peer-' 120; cmd b 'text:Skip'
waitfor a 'Skip|peer-' 120; cmd a 'text:Skip'
waitfor b 'peer-' 60; cmd b 'row'; waitfor b 'Message|Say something' 30; cmd b 'type:hello from b'; sleep 2; cmd b 'send'
waitfor a 'hello from b' 60; cmd a 'row'; waitfor a 'text: peer-' 30; cmd a 'type:hello from a'; sleep 2; cmd a 'send'
waitfor b 'hello from a' 60; inthread b; waitfor b '^text: peer-.*hello from a' 30
xcrun simctl io $B screenshot --mask=black $E/web_composer_b.png >/dev/null 2>&1
log "a thread: $(lastof a 'text:')"; log "b thread: $(lastof b 'text:')"
for try in 1 2 3; do cmd a 'aria:Back'; waitfor a 'Inbox' 8 && break; done; log "a inbox: $(lastof a 'text:')"; for try in 1 2 3; do cmd a 'row'; waitfor a 'text: peer-' 8 && break; done; log "a reopened: $(lastof a 'text:')"
inthread b; cmd b 'type:after reopen'; sleep 2; cmd b 'send'; waitfor a 'after reopen' 60; log "a after reopen: $(lastof a 'text:')"
cmd a "js:(()=>{const v=visualViewport,se=document.scrollingElement,ta=document.querySelector('textarea').getBoundingClientRect();const bs=[...document.querySelectorAll('body *')].filter(e=>/after reopen/.test(e.textContent||'')&&!e.children.length);const lb=bs.length?bs[bs.length-1].getBoundingClientRect():null;const vars=[...document.querySelectorAll('[style*=\"--\"]')].map(e=>e.getAttribute('style').match(/--[^;]+/g).join(',')).join(' / ');return JSON.stringify({sy:scrollY,ih:innerHeight,vh:v.height,vt:v.offsetTop,sh:se.scrollHeight,ch:se.clientHeight,ta:[ta.top,ta.bottom],last:lb&&[lb.top,lb.bottom],vars})})()"; sleep 3; log "probe: $(lastof a 'js ')"
xcrun simctl io $A screenshot --mask=black $E/web_thread.png >/dev/null 2>&1
# The peer link can take a retry to come up (the app reconnects after a failed attempt): give it a while before
# recording it.
if [ -n "$R" ]; then for i in $(seq 1 45); do lastof a '"m":"ice ' | grep -q 'ice connected' && lastof b '"m":"ice ' | grep -q 'ice connected' && break; sleep 1; done; fi
log "ice a: $(lastof a '"m":"ice ' | sed 's/.*"m":"//; s/"}$//')"; log "ice b: $(lastof b '"m":"ice ' | sed 's/.*"m":"//; s/"}$//')"
log "traps: $(grep -c 'Fatal error' $E/weblog.txt)"
log done
pkill -f cmdserver.py; xcrun simctl shutdown $A >/dev/null 2>&1; xcrun simctl shutdown $B >/dev/null 2>&1; log "sims down"

# Convo icon

`Convo.icon` is the Icon Composer document: two linked chat bubbles, mint and
violet, on a dark ground. The iOS and macOS apps compile it through
`app_icons`. The PNGs are its exports for the web client (favicon, touch icon,
and the install manifest's 192 and 512 px sizes); regenerate them after an
edit with Icon Composer's own ictool (the one in Xcode's usr/bin rejects these
flags), then `sips -Z 512` / `sips -Z 192`:

    "/Applications/Xcode.app/Contents/Applications/Icon Composer.app/Contents/Executables/ictool" \
      Convo.icon --export-image --output-file Convo-1024.png \
      --platform iOS --rendition Default --width 1024 --height 1024 --scale 1

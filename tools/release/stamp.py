#!/usr/bin/env python3
"""Stamp asset URLs with a content hash.

Browsers cache the site's JS aggressively (GitHub Pages serves it with a
ten-minute max-age, and a Home Screen web app keeps its copy until it is
relaunched), so a released fix can sit unused behind a stale copy — which
is fatal for an app that updates itself. Appending a hash of each file's
contents makes a URL change exactly when the file does, and never
otherwise.

Stamped: every `src`/`href` in index.html, the `import` specifiers in
index.html's inline modules, and the `import`/`export … from` specifiers
inside the runtime's own modules (runtime/*.js and the root bridge), which
load each other by relative path. The hashes are computed bottom-up so a
module's stamp covers its already-stamped imports.
"""
import hashlib, pathlib, re, sys

site = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "applications/p2prc_web_client")
index = site / "index.html"

SPEC = re.compile(r'''(from\s*|import\s*\(?\s*)(["'])(\.{1,2}/[\w./\-]+\.js)(?:\?v=[0-9a-f]+)?\2''')
ATTR = re.compile(r'(src|href)="((?:\./)?[\w./\-]+\.(?:js|css|webmanifest))(?:\?v=[0-9a-f]+)?"')

digests: dict[pathlib.Path, str] = {}
stamped: set[str] = set()


def digest(path: pathlib.Path) -> str:
    if path not in digests:
        digests[path] = hashlib.sha256(path.read_bytes()).hexdigest()[:8] if path.exists() else "0"
    return digests[path]


def stamp_module(path: pathlib.Path) -> None:
    """Rewrites a module's relative import specifiers, importing modules first."""
    if path in digests or not path.exists():
        return
    text = path.read_text()

    def rewrite(match: re.Match) -> str:
        lead, quote, spec = match.group(1), match.group(2), match.group(3)
        target = (path.parent / spec).resolve()
        if not target.exists():   # a specifier in a comment or an example
            return match.group(0)
        stamp_module(target)
        stamped.add(str(target.relative_to(site.resolve())))
        return f"{lead}{quote}{spec}?v={digest(target)}{quote}"

    new = SPEC.sub(rewrite, text)
    if new != text:
        path.write_text(new)
    digest(path)


for module in sorted(list(site.glob("*.js")) + list(site.glob("runtime/*.js"))):
    stamp_module(module.resolve())

html = index.read_text()


def stamp_attr(match: re.Match) -> str:
    attr, name = match.group(1), match.group(2)
    target = (site / name).resolve()
    stamp_module(target)
    stamped.add(name.removeprefix("./"))
    return f'{attr}="{name}?v={digest(target)}"'


def stamp_inline(match: re.Match) -> str:
    lead, quote, spec = match.group(1), match.group(2), match.group(3)
    target = (site / spec).resolve()
    stamp_module(target)
    stamped.add(spec.removeprefix("./"))
    return f"{lead}{quote}{spec}?v={digest(target)}{quote}"


html = ATTR.sub(stamp_attr, html)
html = SPEC.sub(stamp_inline, html)
index.write_text(html)
print("stamped:", ", ".join(sorted(stamped)))

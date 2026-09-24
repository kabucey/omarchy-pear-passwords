"""A line-of-JSON frontend, so a GUI can drive the sign-in flow.

Protocol, one JSON object per line.

  out   {"event":"step"|"out"|"warn"|"err","text":...}
  ask   {"need":"text"|"secret"|"confirm","prompt":...}   -> reply {"value": "..."}
  end   {"event":"done","ok":true|false,"code":N}

The GUI renders whatever prompt arrives rather than knowing the flow, so a step added to
sign-in later reaches it with no UI change. Secrets travel in-process down a pipe to a child
this process spawned - they are never arguments, never environment, never a file.
"""

from __future__ import annotations

import json
import sys


class JsonFrontend:
    def __init__(self, out_stream=None, in_stream=None):
        self._out = out_stream or sys.stdout
        self._in = in_stream or sys.stdin

    def _send(self, obj: dict) -> None:
        self._out.write(json.dumps(obj) + "\n")
        self._out.flush()

    def _await(self, obj: dict) -> str:
        self._send(obj)
        line = self._in.readline()
        if not line:
            # The GUI closed the pipe: treat it as cancelling, not as an empty answer, or a
            # blank would be submitted as the verification code and burn an attempt.
            raise KeyboardInterrupt("sign-in cancelled")
        try:
            reply = json.loads(line)
        except ValueError:
            raise KeyboardInterrupt("malformed reply")
        if reply.get("cancel"):
            raise KeyboardInterrupt("sign-in cancelled")
        return str(reply.get("value", ""))

    # --- what ui.py calls -------------------------------------------------
    def emit(self, kind: str, text: str) -> None:
        self._send({"event": kind, "text": str(text)})

    def ask(self, prompt: str, kind=None, default=None) -> str:
        return self._await({"need": "text", "kind": kind, "prompt": prompt,
                            "default": default}).strip()

    def secret(self, prompt: str, kind=None, detail=None) -> str:
        return self._await({"need": "secret", "kind": kind, "prompt": prompt, "detail": detail})

    def confirm_yn(self, prompt: str, kind=None, detail=None) -> bool:
        reply = self._await({"need": "confirm", "kind": kind, "prompt": prompt, "detail": detail})
        return reply.strip().lower() in ("y", "yes", "true")

    def stage(self, stage_name: str, **info) -> None:
        self._send({"event": "stage", "stage": stage_name, **info})

    def choose(self, prompt: str, options: list, kind=None, details=None):
        reply = self._await({"need": "choice", "kind": kind, "prompt": prompt,
                             "options": [str(o) for o in options],
                             "details": [str(d) for d in (details or [""] * len(options))]})
        return int(reply) if reply.strip().isdigit() and int(reply) < len(options) else None

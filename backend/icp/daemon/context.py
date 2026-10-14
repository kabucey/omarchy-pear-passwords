"""What the Apple pipeline runs with inside the daemon: one user's store and, sometimes, a
person to ask.

The daemon builds a UserContext for every Apple call; daemon/apple.py consumes it. The Frontend
is the interface cli/jsonui.py already implements (emit, stage, ask, secret, confirm_yn,
choose), so every prompt the sign-in flow has today - and any Apple adds later - reaches the
Pear window over the socket without the flow knowing where it is drawn.

A background run (the scheduler's sync, the sync after unlock) has no frontend. Anything that
would need an answer from a person then raises NeedsLogin instead of blocking or falling back
to a terminal prompt: the daemon has no terminal, and a prompt nobody asked for is exactly what
2.0 exists to remove.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..vstore import UserStore


class NeedsLogin(Exception):
    """Apple wants something only a person can give (password, 2FA code, device passcode)
    and there is no frontend to ask. The daemon records needs_login and emits `needs-login`."""


class Cancelled(KeyboardInterrupt):
    """The person cancelled a question, or the UI connection went away mid-flow.

    Derived from KeyboardInterrupt, as the 1.x jsonui cancel was, so the many broad
    `except Exception` blocks in the Apple code cannot swallow it and carry on half signed in.
    The daemon catches it at the top of the signin handler."""


@runtime_checkable
class Frontend(Protocol):
    """A place to show sign-in progress and ask questions. Implemented by the daemon's socket
    frontend (daemon/frontend.py) and, for development only, by cli/jsonui.JsonFrontend.

    Every asking method blocks the calling worker thread until the answer arrives, and raises
    Cancelled if the person cancels or the connection closes."""

    def emit(self, kind: str, text: str) -> None:
        """A line of progress: kind is "step", "out", "warn" or "err"."""
        ...

    def stage(self, stage_name: str, **info) -> None:
        """Where the flow has got to ("account", "signing_in", "verify", "syncing", ...)."""
        ...

    def ask(self, prompt: str, kind: str | None = None, default: str | None = None) -> str:
        """A visible text answer (Apple ID, 2FA code). `kind` tells the UI which input to draw."""
        ...

    def secret(self, prompt: str, kind: str | None = None, detail: str | None = None) -> str:
        """A hidden answer (Apple ID password, device passcode). Never logged or echoed."""
        ...

    def confirm_yn(self, prompt: str, kind: str | None = None,
                   detail: str | None = None) -> bool:
        """Yes/no, defaulting to no."""
        ...

    def choose(self, prompt: str, options: list, kind: str | None = None,
               details: list | None = None) -> int | None:
        """Index into `options`, or None to abort."""
        ...


class BackgroundFrontend:
    """The frontend of a run with nobody to ask: progress is dropped, questions raise
    NeedsLogin. UserContext.ui returns one of these when frontend is None."""

    interactive = False          # nobody to answer: never trigger an Apple 2FA push

    def emit(self, kind: str, text: str) -> None:
        return None

    def stage(self, stage_name: str, **info) -> None:
        return None

    def ask(self, prompt: str, kind: str | None = None, default: str | None = None) -> str:
        raise NeedsLogin(kind or "text")

    def secret(self, prompt: str, kind: str | None = None, detail: str | None = None) -> str:
        raise NeedsLogin(kind or "secret")

    def confirm_yn(self, prompt: str, kind: str | None = None,
                   detail: str | None = None) -> bool:
        raise NeedsLogin(kind or "confirm")

    def choose(self, prompt: str, options: list, kind: str | None = None,
               details: list | None = None) -> int | None:
        raise NeedsLogin(kind or "choice")


@dataclass
class UserContext:
    """One user's Apple work: whose it is, their unlocked store, where anisette is, and who
    (if anyone) can answer questions.

    `store` must be unlocked (tier 1) for every call that reads or writes the session or the
    entries; daemon/apple.py never unseals anything itself. `frontend` is None for background
    runs; use `ui` rather than `frontend` so a missing person turns into NeedsLogin."""

    uid: int
    store: "UserStore"
    anisette_url: str
    frontend: Frontend | None = None
    # Set by a full sync: (class, agrp) counts and attribute names of what it decrypted, no
    # value (vault.host.strip_and_shape). The daemon keeps it for op diag-items.
    item_shape: dict | None = None

    @property
    def interactive(self) -> bool:
        return self.frontend is not None

    @property
    def ui(self) -> Frontend:
        return self.frontend if self.frontend is not None else BackgroundFrontend()

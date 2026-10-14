# native/

`pear-exec.c` is the set-gid shim that is the only way to get effective gid `pear-client`, and
so the only way to reach the daemon socket. It is compiled from source by the root install step
and never shipped as a binary:

```sh
cc -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -pie -Wl,-z,relro,-z,now \
   -o pear-exec native/pear-exec.c
install -m2755 -o root -g pear-client pear-exec /usr/local/lib/pear-passwords/libexec/pear-exec
```

What it does (spec section 4.4, plus the fourth role):

- exactly one argument, one of `ui`, `clip`, `migrate`, `autofill`; anything else exits 64;
- refuses root, refuses unless it really runs set-gid `pear-client`, and refuses a caller who
  is a member of `pear-client`;
- checks `XDG_RUNTIME_DIR` (`/run/user/<uid>`, yours, 0700), `WAYLAND_DISPLAY` (a bare
  `wayland-N` name whose socket is yours and is served by the oldest Hyprland you own, the one
  named in its `hyprland.lock`) and `DBUS_SESSION_BUS_ADDRESS`;
- builds the environment from scratch (see the source for the exact list), sets umask 077 and
  no_new_privs, closes every fd above 2 and keeps stdin and stdout for every role;
- execs the role's fixed argv only after checking that the target, every parent directory,
  the app directory or venv, `fonts.conf` and the empty XDG directory are root-owned and not
  group- or other-writable, following symlinks and checking where they lead too.

Every path and name it hard-codes equals `system/paths.env`. `backend/tests/test_pear_exec_env.py`
checks that, builds it with `-DPEAR_EXEC_TEST_MODE` in a scratch directory (paths under
`$PEAR_EXEC_TEST_ROOT`, "root-owned" meaning owned by the test user, no set-gid check) to test the
environment and every refusal against a fake compositor, and builds it the installer's way to
prove the test variables do nothing there.

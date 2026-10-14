"""Client programs started through pear-exec: clip, migrate and autofill.

Each runs as the user with egid pear-client, non-dumpable, from the root-owned venv with
`python -I`. They talk to the daemon over paths.SOCKET_PATH using docs/protocol.md and must
keep their imports small: nothing from icp.daemon beyond paths and protocol.
"""

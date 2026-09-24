"""Common base for the package's Apple-protocol exceptions."""


class AppleError(RuntimeError):
    """Base for every error raised against an Apple service or its wire formats."""


class EncryptedStoreError(AppleError):
    """An encrypted local store exists but cannot be trusted or rewritten safely."""


class PassphraseMigrationError(EncryptedStoreError):
    """Passphrase conversion failed and its rollback could not complete cleanly."""

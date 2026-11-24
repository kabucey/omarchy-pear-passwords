"""Apple Passwords shared groups: PCS decryption, read-only fetches and the diagnostic."""


def bump(counter: dict, key: str, n: int = 1) -> None:
    """counter[key] += n, starting from 0."""
    counter[key] = counter.get(key, 0) + n

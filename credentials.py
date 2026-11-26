#!/usr/bin/env python3
"""Generate and persist a short random UI password, using standard library only.

Never write passwords to application logs. The installer deliberately prints
credentials once at the end, to the invoking administrator's terminal.
"""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import string
import tempfile

PASSWORD_LENGTH = 12
ALPHABET = string.ascii_letters + string.digits


def new_password():
    """12 cryptographically-random alphanumeric characters (~71 bits)."""
    return ''.join(secrets.choice(ALPHABET) for _ in range(PASSWORD_LENGTH))


def ensure_credentials(root: Path):
    """Return (password, action), preserving existing short passwords.

    Previous versions created a 43-character urlsafe token. Rotate only that
    recognizable legacy format when upgrading to 2.0.4; unrelated custom
    passwords remain untouched (otherwise upgrades could lock an admin out).
    """
    root = Path(root)
    token = root / 'ui-token'
    if token.is_symlink():
        raise ValueError('refusing to use symlink for ui-token')
    if token.exists():
        existing = token.read_text(encoding='utf-8').strip()
        if not existing:
            raise ValueError('ui-token is empty; refusing silent reinitialization')
        # 2.0.1-2.0.3: secrets.token_urlsafe(32) => exactly 43 chars.
        legacy = len(existing) == 43 and all(c in (ALPHABET + '-_') for c in existing)
        if not legacy:
            os.chmod(token, 0o600)
            return existing, 'preserved'
        action = 'rotated-legacy'
    else:
        action = 'created'
    password = new_password()
    fd, temp = tempfile.mkstemp(prefix='.ui-token-', dir=root)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(password + '\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, token)
        os.chmod(token, 0o600)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return password, action


def main():
    password, action = ensure_credentials(Path('/opt/fw-sentinel'))
    # Called from installer, captured in a root-only shell variable, printed
    # only after service installation succeeds.
    print(action)
    print(password)


if __name__ == '__main__':
    main()

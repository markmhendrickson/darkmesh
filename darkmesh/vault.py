import json
import os
from typing import Any, Dict, List

from cryptography.fernet import Fernet


class EncryptedVault:
    def __init__(self, root: str) -> None:
        self.root = root
        os.makedirs(self.root, exist_ok=True)
        self.key_path = os.path.join(self.root, "vault.key")
        self._fernet = Fernet(self._load_or_create_key())

    def _secure_permissions(self, path: str) -> None:
        try:
            os.chmod(path, 0o600)
        except OSError:
            # Best-effort on platforms/filesystems that do not support POSIX chmod.
            pass

    def _load_or_create_key(self) -> bytes:
        if os.path.exists(self.key_path):
            self._secure_permissions(self.key_path)
            with open(self.key_path, "rb") as f:
                return f.read()

        key = Fernet.generate_key()
        fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        self._secure_permissions(self.key_path)
        return key

    def _dataset_path(self, name: str) -> str:
        safe = name.replace("/", "_")
        return os.path.join(self.root, f"{safe}.enc")

    def load(self, name: str) -> List[Dict[str, Any]]:
        path = self._dataset_path(name)
        if not os.path.exists(path):
            return []
        with open(path, "rb") as f:
            encrypted = f.read()
        if not encrypted:
            return []
        data = self._fernet.decrypt(encrypted)
        return json.loads(data.decode("utf-8"))

    def store(self, name: str, records: List[Dict[str, Any]]) -> None:
        path = self._dataset_path(name)
        payload = json.dumps(records, ensure_ascii=True).encode("utf-8")
        encrypted = self._fernet.encrypt(payload)
        with open(path, "wb") as f:
            f.write(encrypted)

    def append(self, name: str, records: List[Dict[str, Any]]) -> int:
        existing = self.load(name)
        existing.extend(records)
        self.store(name, existing)
        return len(existing)

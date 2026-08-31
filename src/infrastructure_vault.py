"""Cyber Terrafor Professional v11.0 encrypted infrastructure vault.

Secrets are encrypted with a random vault master key. The master key is wrapped
with a password-derived KEK; the administrator password is never persisted or
stored in the session. Each site record is separately authenticated with AES-GCM.
"""
from pathlib import Path
import base64, hashlib, json, os, secrets, tempfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KDF_ITERS = 390_000
MAGIC = "CYBERTOR-VAULT-2"

class VaultError(Exception): pass

class Vault:
    def __init__(self, state, key=None, password=None):
        self.path = Path(state) / 'infrastructure.vault.json'
        self.state = Path(state)
        self.state.mkdir(parents=True, exist_ok=True)
        self._key = key
        if password is not None and key is None:
            self._key = self._unlock_password(password)
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text())
            except Exception as e:
                raise VaultError('Vault file is invalid or corrupt') from e
        else:
            self.data = None

    @staticmethod
    def _kek(password, salt):
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, KDF_ITERS, 32)

    def _unlock_password(self, password):
        if not self.path.exists():
            salt = secrets.token_bytes(16)
            master = secrets.token_bytes(32)
            kek = self._kek(password, salt)
            nonce = secrets.token_bytes(12)
            wrapped = AESGCM(kek).encrypt(nonce, master, MAGIC.encode())
            self.data = {'format': MAGIC, 'kdf': 'PBKDF2-HMAC-SHA256', 'iterations': KDF_ITERS,
                         'salt': base64.b64encode(salt).decode(), 'wrap_nonce': base64.b64encode(nonce).decode(),
                         'wrapped_key': base64.b64encode(wrapped).decode(), 'items': {}}
            self._atomic_save()
            return master
        d = json.loads(self.path.read_text())
        if d.get('format') != MAGIC:
            raise VaultError('Unsupported vault format; migrate the vault before use')
        salt = base64.b64decode(d['salt'])
        kek = self._kek(password, salt)
        try:
            return AESGCM(kek).decrypt(base64.b64decode(d['wrap_nonce']), base64.b64decode(d['wrapped_key']), MAGIC.encode())
        except Exception as e:
            raise VaultError('Vault unlock failed') from e

    def _atomic_save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix='.vault-', dir=str(self.path.parent))
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(self.data, f, indent=2); f.flush(); os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)

    def _ensure_key(self):
        if not self._key: raise VaultError('Vault is locked')
        if not self.data: self.data = json.loads(self.path.read_text()) if self.path.exists() else None
        if not self.data: raise VaultError('Vault is not initialized')

    def change_password(self, old_password, new_password):
        """Re-wrap the existing random vault master key with a new password."""
        if not self.path.exists():
            # Initialize the vault under the new password when it has never been used.
            self._unlock_password(new_password)
            self._atomic_save()
            return
        old_key = self._unlock_password(old_password)
        data = self.data
        salt = secrets.token_bytes(16)
        kek = self._kek(new_password, salt)
        nonce = secrets.token_bytes(12)
        wrapped = AESGCM(kek).encrypt(nonce, old_key, MAGIC.encode())
        data['salt'] = base64.b64encode(salt).decode()
        data['wrap_nonce'] = base64.b64encode(nonce).decode()
        data['wrapped_key'] = base64.b64encode(wrapped).decode()
        data['kdf'] = 'PBKDF2-HMAC-SHA256'
        data['iterations'] = KDF_ITERS
        self._key = old_key
        self._atomic_save()

    def put(self, sid, obj):
        self._ensure_key()
        nonce = secrets.token_bytes(12)
        aad = ('site:' + sid).encode()
        ct = AESGCM(self._key).encrypt(nonce, json.dumps(obj, separators=(',', ':')).encode(), aad)
        self.data['items'][sid] = {'nonce': base64.b64encode(nonce).decode(), 'ct': base64.b64encode(ct).decode()}
        self._atomic_save()

    def get(self, sid):
        self._ensure_key()
        x = self.data.get('items', {}).get(sid)
        if not x: return None
        return json.loads(AESGCM(self._key).decrypt(base64.b64decode(x['nonce']), base64.b64decode(x['ct']), ('site:' + sid).encode()))

    def has(self, sid):
        self._ensure_key(); return sid in self.data.get('items', {})

    def delete(self, sid):
        self._ensure_key(); self.data.get('items', {}).pop(sid, None); self._atomic_save()

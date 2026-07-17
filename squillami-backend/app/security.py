"""Hashing, token e validazione firma Twilio. Solo librerie standard."""
import base64
import hashlib
import hmac
import os
import secrets

# Chiave segreta del server: OBBLIGATORIA in produzione (variabile d'ambiente SECRET_KEY)
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")


def code_hash(code: str) -> str:
    """HMAC del codice di sblocco: usato per verificare il codice DOPO aver
    identificato l'utente dal numero. Non più univoco: il codice è libero."""
    return hmac.new(SECRET_KEY.encode(), f"code:{code}".encode(), hashlib.sha256).hexdigest()


def normalize_phone(raw: str) -> str:
    """Normalizza un numero: tiene solo le cifre e prende le ultime 10
    (così '+39 340 1234567' e '3401234567' coincidono)."""
    digits = "".join(c for c in raw if c.isdigit())
    return digits[-10:] if len(digits) >= 10 else digits


def phone_lookup(raw: str) -> str:
    """HMAC deterministico del numero normalizzato: identifica l'utente."""
    return hmac.new(SECRET_KEY.encode(), f"phone:{normalize_phone(raw)}".encode(),
                    hashlib.sha256).hexdigest()


def new_api_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(f"{SECRET_KEY}:{token}".encode()).hexdigest()


def verify_token(token: str, token_hash: str) -> bool:
    return hmac.compare_digest(hash_token(token), token_hash)


def verify_code(code: str, stored_hash: str) -> bool:
    return hmac.compare_digest(code_hash(code), stored_hash or "")


def valid_code_format(code: str) -> bool:
    return code.isdigit() and 4 <= len(code) <= 10


def valid_phone_format(raw: str) -> bool:
    return len(normalize_phone(raw)) >= 6


def validate_twilio_signature(url: str, params: dict, signature: str) -> bool:
    """Verifica X-Twilio-Signature (HMAC-SHA1 di URL + parametri ordinati).
    Se TWILIO_AUTH_TOKEN non è impostato (sviluppo locale) la verifica è disattivata."""
    if not TWILIO_AUTH_TOKEN:
        return True
    payload = url + "".join(k + params[k] for k in sorted(params))
    digest = hmac.new(TWILIO_AUTH_TOKEN.encode(), payload.encode(), hashlib.sha1).digest()
    expected = base64.b64encode(digest).decode()
    return hmac.compare_digest(expected, signature or "")

"""Hashing, token e validazione firma Twilio. Solo librerie standard."""
import base64
import hashlib
import hmac
import os
import secrets

# Chiave segreta del server: OBBLIGATORIA in produzione (variabile d'ambiente SECRET_KEY)
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "")   # Cloudflare Turnstile (CAPTCHA, opzionale)
POW_BITS = int(os.environ.get("POW_BITS", "16"))            # difficoltà proof-of-work (multipli di 4). 0 = disattivata
POW_TTL = int(os.environ.get("POW_TTL", "300"))            # secondi di validità di una sfida


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


def new_find_token() -> str:
    """Token effimero per la sessione web che legge la posizione."""
    return secrets.token_urlsafe(24)


def verify_captcha(token: str, remoteip: str | None = None) -> bool:
    """Verifica il CAPTCHA (Cloudflare Turnstile). Se il secret non è
    configurato (sviluppo) la verifica è disattivata e ritorna True."""
    if not TURNSTILE_SECRET:
        return True
    try:  # pragma: no cover - richiede rete e secret reale
        import urllib.parse
        import urllib.request
        data = {"secret": TURNSTILE_SECRET, "response": token or ""}
        if remoteip:
            data["remoteip"] = remoteip
        req = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=urllib.parse.urlencode(data).encode())
        with urllib.request.urlopen(req, timeout=6) as resp:
            import json
            return bool(json.load(resp).get("success"))
    except Exception:
        return False


# --- Proof-of-work self-hosted (anti-bot senza servizi esterni) -------------
# Il server emette una sfida firmata (HMAC, stateless). Il browser deve trovare
# un nonce tale che sha256("seed.ts.bits.nonce") inizi con `bits/4` zeri esadecimali.
# Costo per il client ~ 2^bits hash; per noi la verifica è un solo hash.

def _pow_sig(seed: str, ts: int, bits: int) -> str:
    return hmac.new(SECRET_KEY.encode(), f"{seed}.{int(ts)}.{bits}".encode(),
                    hashlib.sha256).hexdigest()[:32]


def make_pow(now_ts: int) -> dict:
    """Crea una nuova sfida proof-of-work firmata."""
    seed = secrets.token_hex(8)
    return {"seed": seed, "ts": int(now_ts), "bits": POW_BITS,
            "sig": _pow_sig(seed, now_ts, POW_BITS)}


def verify_pow(seed: str, ts, bits, sig: str, nonce: str, now_ts: int) -> bool:
    """Verifica una soluzione proof-of-work. Se POW_BITS<=0 la verifica è disattivata."""
    if POW_BITS <= 0:
        return True
    try:
        ts = int(ts); bits = int(bits)
    except (TypeError, ValueError):
        return False
    if not seed or not sig:
        return False
    if not hmac.compare_digest(_pow_sig(seed, ts, bits), sig or ""):
        return False          # sfida non emessa da noi o manomessa
    if bits < POW_BITS:
        return False          # difficoltà abbassata
    if abs(now_ts - ts) > POW_TTL:
        return False          # sfida scaduta
    digest = hashlib.sha256(f"{seed}.{ts}.{bits}.{nonce}".encode()).hexdigest()
    return digest.startswith("0" * (bits // 4))


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

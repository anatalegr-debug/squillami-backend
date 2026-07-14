"""Invio SMS con la posizione, via Twilio REST.

Se le credenziali Twilio sono configurate (TWILIO_ACCOUNT_SID +
TWILIO_AUTH_TOKEN + TWILIO_SMS_FROM) l'SMS viene inviato davvero.
Altrimenti viene solo scritto nel log: utile per i test senza upgrade
dell'account (gli account trial non inviano SMS a numeri non verificati).
"""
import base64
import logging
import os
import urllib.parse
import urllib.request

log = logging.getLogger("squillami.sms")

ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID", "")
AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")
SMS_FROM = os.environ.get("TWILIO_SMS_FROM", "")   # numero mittente Twilio


def send_location(to: str, address: str, maps_url: str, when: str) -> bool:
    """Invia un SMS con l'ultima posizione nota. Ritorna True se inviato/simulato."""
    body = (f"Squillami: il tuo telefono e' stato localizzato.\n"
            f"{address}\n{maps_url}\n(rilevato: {when} UTC)")

    if not (ACCOUNT_SID and AUTH_TOKEN and SMS_FROM):
        log.info("SMS SIMULATO -> a=%s | %s", to, body.replace("\n", " | "))
        return True

    try:  # pragma: no cover - richiede account Twilio a pagamento
        url = f"https://api.twilio.com/2010-04-01/Accounts/{ACCOUNT_SID}/Messages.json"
        data = urllib.parse.urlencode({"To": to, "From": SMS_FROM, "Body": body}).encode()
        req = urllib.request.Request(url, data=data)
        cred = base64.b64encode(f"{ACCOUNT_SID}:{AUTH_TOKEN}".encode()).decode()
        req.add_header("Authorization", f"Basic {cred}")
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status in (200, 201)
    except Exception as exc:
        log.error("Errore invio SMS: %s", exc)
        return False

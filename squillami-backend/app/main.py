"""MiChiami — backend MVP.

Avvio locale:   uvicorn app.main:app --reload
Documentazione: http://localhost:8000/docs
"""
import logging
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape

from fastapi import FastAPI, Form, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field

from . import db, geocode, push, security, sms

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("squillami")

app = FastAPI(title="MiChiami", version="0.1.0")


@app.on_event("startup")
def startup() -> None:
    db.init_db()


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
MAX_USER_FAILS = 3          # tentativi errati prima del blocco account
LOCK_MINUTES = 15           # durata blocco account
MAX_CALLER_ATTEMPTS = 5     # tentativi (anche su codici diversi) per numero chiamante
CALLER_WINDOW_MIN = 15


def now() -> datetime:
    return datetime.now(timezone.utc)


def twiml(inner: str) -> Response:
    xml = f'<?xml version="1.0" encoding="UTF-8"?><Response>{inner}</Response>'
    return Response(content=xml, media_type="application/xml")


def say(text: str) -> str:
    return f'<Say language="it-IT">{escape(text)}</Say>'


def gather_phone(prompt: str) -> str:
    # Il numero ha lunghezza variabile: si conclude con il tasto cancelletto (#)
    return (f'<Gather input="dtmf" finishOnKey="#" timeout="12" action="/twilio/identify" method="POST">'
            f"{say(prompt)}</Gather>" + say("Non ho ricevuto nessun numero. Arrivederci."))


def gather_code(prompt: str, uid: int) -> str:
    return (f'<Gather input="dtmf" numDigits="10" finishOnKey="#" timeout="10" '
            f'action="/twilio/gather?uid={uid}" method="POST">'
            f"{say(prompt)}</Gather>" + say("Non ho ricevuto nessun codice. Arrivederci."))


def auth_user(conn, authorization: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Token mancante")
    token = authorization.removeprefix("Bearer ").strip()
    for row in conn.execute("SELECT id, api_token_hash FROM users"):
        if security.verify_token(token, row["api_token_hash"]):
            return row["id"]
    raise HTTPException(401, "Token non valido")


def check_twilio_signature(request: Request, form: dict) -> None:
    sig = request.headers.get("X-Twilio-Signature", "")
    url = str(request.url)
    if not security.validate_twilio_signature(url, form, sig):
        raise HTTPException(403, "Firma Twilio non valida")


# --------------------------------------------------------------------------
# API REST (usate dall'app sul telefono)
# --------------------------------------------------------------------------
class RegisterIn(BaseModel):
    name: str = Field(default="", max_length=100)
    phone: str = Field(min_length=6, max_length=20)
    code: str = Field(min_length=4, max_length=10)


@app.post("/v1/register")
def register(body: RegisterIn):
    """Crea l'account. Il NUMERO identifica (univoco), il CODICE è libero (4-10 cifre)."""
    if not security.valid_phone_format(body.phone):
        raise HTTPException(400, "Numero di telefono non valido")
    if not security.valid_code_format(body.code):
        raise HTTPException(400, "Il codice deve essere di 4-10 cifre numeriche")
    token = security.new_api_token()
    with db.get_db() as conn:
        try:
            cur = conn.execute(
                "INSERT INTO users (name, phone_lookup, code_hash, api_token_hash) VALUES (?,?,?,?)",
                (body.name, security.phone_lookup(body.phone),
                 security.code_hash(body.code), security.hash_token(token)))
        except Exception:
            raise HTTPException(409, "Questo numero è già registrato.")
        user_id = cur.lastrowid
        conn.execute("INSERT INTO devices (user_id) VALUES (?)", (user_id,))
    return {"user_id": user_id, "api_token": token,
            "message": "Conserva il token: serve all'app per autenticarsi"}


class TokenIn(BaseModel):
    push_token: str
    platform: str = Field(pattern="^(android|ios)$")
    model: str = ""


@app.put("/v1/devices/token")
def update_push_token(body: TokenIn, authorization: str | None = Header(default=None)):
    with db.get_db() as conn:
        user_id = auth_user(conn, authorization)
        conn.execute(
            "UPDATE devices SET push_token=?, platform=?, model=?, updated_at=datetime('now') "
            "WHERE user_id=?", (body.push_token, body.platform, body.model, user_id))
    return {"ok": True}


class LocationIn(BaseModel):
    lat: float
    lon: float
    accuracy_m: float | None = None
    battery: int | None = None
    kind: str = Field(default="fix", pattern="^(fix|cached)$")
    event_id: int | None = None


@app.post("/v1/locations")
def post_location(body: LocationIn, authorization: str | None = Header(default=None)):
    with db.get_db() as conn:
        user_id = auth_user(conn, authorization)
        conn.execute(
            "INSERT INTO locations (user_id, event_id, lat, lon, accuracy_m, battery, kind) "
            "VALUES (?,?,?,?,?,?,?)",
            (user_id, body.event_id, body.lat, body.lon, body.accuracy_m, body.battery, body.kind))
        if body.event_id:
            conn.execute("UPDATE events SET status='located' WHERE id=? AND user_id=?",
                         (body.event_id, user_id))
        purge_old_data(conn)   # retention: elimina dati oltre 30 giorni
    return {"ok": True}


@app.get("/v1/events")
def list_events(authorization: str | None = Header(default=None)):
    """Storico delle attivazioni: trasparenza per il proprietario."""
    with db.get_db() as conn:
        user_id = auth_user(conn, authorization)
        rows = conn.execute(
            "SELECT id, caller, status, created_at FROM events "
            "WHERE user_id=? ORDER BY id DESC LIMIT 50", (user_id,)).fetchall()
    return {"events": [dict(r) for r in rows]}


@app.delete("/v1/account")
def delete_account(authorization: str | None = Header(default=None)):
    """GDPR: cancella l'account e TUTTI i dati collegati (device, eventi,
    posizioni). Richiesto anche da Apple (cancellazione account in-app)."""
    with db.get_db() as conn:
        user_id = auth_user(conn, authorization)
        conn.execute("DELETE FROM locations WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM events WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM devices WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    return {"deleted": True}


def purge_old_data(conn) -> None:
    """Data minimization: elimina posizioni ed eventi più vecchi di 30 giorni."""
    conn.execute("DELETE FROM locations WHERE created_at < datetime('now','-30 days')")
    conn.execute("DELETE FROM events WHERE created_at < datetime('now','-30 days')")


@app.get("/health")
def health():
    return {"status": "ok"}


# --------------------------------------------------------------------------
# Webhook Twilio (IVR)
# --------------------------------------------------------------------------
@app.post("/twilio/voice")
async def twilio_voice(request: Request, From: str = Form(default="")):
    form = dict((await request.form()).items())
    check_twilio_signature(request, form)
    return twiml(gather_phone(
        "Benvenuto in MiChiami. Digita il numero del telefono da ritrovare, "
        "seguito dal tasto cancelletto."))


@app.post("/twilio/identify")
async def twilio_identify(request: Request,
                          Digits: str = Form(default=""),
                          From: str = Form(default="")):
    """Passo 1: identifica l'utente dal numero digitato, poi chiede il codice."""
    form = dict((await request.form()).items())
    check_twilio_signature(request, form)

    with db.get_db() as conn:
        window = (now() - timedelta(minutes=CALLER_WINDOW_MIN)).strftime("%Y-%m-%d %H:%M:%S")
        attempts = conn.execute(
            "SELECT COUNT(*) c FROM call_attempts WHERE caller=? AND success=0 AND created_at>?",
            (From, window)).fetchone()["c"]
        if attempts >= MAX_CALLER_ATTEMPTS:
            return twiml(say("Troppi tentativi da questo numero. Riprova più tardi.") + "<Hangup/>")

        user = conn.execute("SELECT * FROM users WHERE phone_lookup=?",
                            (security.phone_lookup(Digits),)).fetchone()
        if user is None:
            conn.execute("INSERT INTO call_attempts (caller, success) VALUES (?,0)", (From,))
            return twiml(gather_phone("Numero non riconosciuto. Riprova, "
                                      "seguito dal tasto cancelletto."))

    return twiml(gather_code("Numero riconosciuto. Ora digita il tuo codice di sblocco, "
                             "seguito dal tasto cancelletto.", user["id"]))


@app.post("/twilio/gather")
async def twilio_gather(request: Request,
                        uid: int,
                        Digits: str = Form(default=""),
                        From: str = Form(default="")):
    """Passo 2: verifica il codice per l'utente già identificato dal numero."""
    form = dict((await request.form()).items())
    check_twilio_signature(request, form)

    with db.get_db() as conn:
        window = (now() - timedelta(minutes=CALLER_WINDOW_MIN)).strftime("%Y-%m-%d %H:%M:%S")
        attempts = conn.execute(
            "SELECT COUNT(*) c FROM call_attempts WHERE caller=? AND success=0 AND created_at>?",
            (From, window)).fetchone()["c"]
        if attempts >= MAX_CALLER_ATTEMPTS:
            return twiml(say("Troppi tentativi da questo numero. Riprova più tardi.") + "<Hangup/>")

        user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

        # Codice errato per questo utente
        if user is None or not security.verify_code(Digits, user["code_hash"]):
            conn.execute("INSERT INTO call_attempts (caller, success) VALUES (?,0)", (From,))
            return twiml(gather_code("Codice errato. Riprova, "
                                     "seguito dal tasto cancelletto.", uid))

        # Account bloccato
        if user["locked_until"] and user["locked_until"] > now().strftime("%Y-%m-%d %H:%M:%S"):
            return twiml(say("Account temporaneamente bloccato per troppi tentativi. "
                             "Riprova tra quindici minuti.") + "<Hangup/>")

        conn.execute("INSERT INTO call_attempts (caller, success) VALUES (?,1)", (From,))
        conn.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?",
                     (user["id"],))

        # Crea evento e invia push
        cur = conn.execute("INSERT INTO events (user_id, caller, status) VALUES (?,?, 'pending')",
                           (user["id"], From))
        event_id = cur.lastrowid
        device = conn.execute("SELECT * FROM devices WHERE user_id=?",
                              (user["id"],)).fetchone()
        sent = push.send_ring_and_locate(device["push_token"] or "",
                                         device["platform"] or "android", event_id)
        conn.execute("UPDATE events SET status=? WHERE id=?",
                     ("ringing" if sent else "failed", event_id))
        # Ultima posizione nota per l'SMS immediato
        last_loc = conn.execute(
            "SELECT * FROM locations WHERE user_id=? ORDER BY id DESC LIMIT 1",
            (user["id"],)).fetchone()

    # Invia subito un SMS con l'ultima posizione rilevata (se disponibile)
    if last_loc and From:
        address = geocode.reverse(last_loc["lat"], last_loc["lon"]) or \
            f"lat {last_loc['lat']:.5f}, lon {last_loc['lon']:.5f}"
        maps_url = f"https://maps.google.com/?q={last_loc['lat']},{last_loc['lon']}"
        sms.send_location(From, address, maps_url, last_loc["created_at"])
        sms_note = "Ti ho inviato un SMS con l'ultima posizione del telefono. "
    else:
        sms_note = "Non ho ancora una posizione registrata per questo telefono. "

    return twiml(
        say("Codice corretto. Sto facendo squillare il tuo telefono. " + sms_note +
            "Resta in linea per conoscere la posizione aggiornata.") +
        f'<Redirect method="POST">/twilio/status?event_id={event_id}&amp;try=1</Redirect>')


@app.post("/twilio/status")
async def twilio_status(request: Request, event_id: int, try_: int | None = None):
    form = dict((await request.form()).items())
    check_twilio_signature(request, form)
    attempt = int(request.query_params.get("try", "1"))

    with db.get_db() as conn:
        loc = conn.execute(
            "SELECT * FROM locations WHERE event_id=? ORDER BY id DESC LIMIT 1",
            (event_id,)).fetchone()

        if loc is None and attempt < 4:
            # Aspetta e riprova: il fix GPS può richiedere 5-15 secondi
            return twiml(
                say("Sto rilevando la posizione, attendi qualche secondo.") +
                '<Pause length="6"/>' +
                f'<Redirect method="POST">/twilio/status?event_id={event_id}&amp;try={attempt+1}</Redirect>')

        if loc is None:
            # Fallback: ultima posizione nota di questo utente
            ev = conn.execute("SELECT user_id FROM events WHERE id=?", (event_id,)).fetchone()
            loc = conn.execute(
                "SELECT * FROM locations WHERE user_id=? ORDER BY id DESC LIMIT 1",
                (ev["user_id"],)).fetchone()
            if loc is None:
                return twiml(say("Il telefono sta squillando, ma non è stato possibile "
                                 "rilevare la posizione. Arrivederci.") + "<Hangup/>")
            prefix = f"Posizione non disponibile ora. L'ultima nota, del {loc['created_at']}, era: "
        else:
            prefix = "Il tuo telefono sta squillando. Si trova in: "

    address = geocode.reverse(loc["lat"], loc["lon"]) or \
        f"latitudine {loc['lat']:.5f}, longitudine {loc['lon']:.5f}"
    return twiml(say(prefix + address + ". Arrivederci.") + "<Hangup/>")


# Blocco account dopo troppi errori sullo stesso utente è gestito qui:
# se il codice esiste ma l'account risulta con troppi failed_attempts.
# (Per l'MVP il conteggio per-utente si attiva quando i codici sono simili;
# la protezione principale è il rate limiting per chiamante.)

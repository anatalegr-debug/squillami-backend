# Squillami — Backend (MVP)

Il server che risponde alla chiamata, verifica il codice di sblocco e fa
squillare/localizzare il telefono. Guida pensata per chi parte da zero:
segui i passi nell'ordine, senza saltarne nessuno.

---

## Passo 1 — Provalo sul tuo computer (10 minuti)

Serve solo Python (gratuito).

1. **Installa Python**: vai su https://www.python.org/downloads/ e scarica
   l'ultima versione. Durante l'installazione su Windows spunta la casella
   **"Add Python to PATH"**.
2. **Apri il terminale**: su Mac cerca "Terminale", su Windows cerca "PowerShell".
3. **Entra nella cartella del progetto** (trascina la cartella nel terminale
   dopo aver scritto `cd `):
   ```
   cd percorso/di/squillami-backend
   ```
4. **Installa le librerie** (una volta sola):
   ```
   pip install -r requirements.txt
   ```
5. **Avvia il server**:
   ```
   uvicorn app.main:app --reload
   ```
   Se vedi `Uvicorn running on http://127.0.0.1:8000` funziona.
6. **Aprilo nel browser**: http://localhost:8000/docs — è la documentazione
   interattiva: da qui puoi provare ogni funzione cliccando "Try it out".

### Simula tutto il flusso senza telefono

Nel sito http://localhost:8000/docs:

1. `POST /v1/register` → inserisci `{"name": "Andrea", "code": "123456"}` →
   ricevi un `api_token`. **Copialo.**
2. Apri un secondo terminale e simula la telefonata di Twilio:
   ```
   curl -X POST http://localhost:8000/twilio/gather -d "Digits=123456" -d "From=%2B39333"
   ```
   Nella finestra del server vedrai `PUSH SIMULATA`: è il momento in cui il
   telefono squillerebbe.
3. Simula il telefono che invia la posizione (usa il tuo api_token e
   l'event_id=1):
   ```
   curl -X POST http://localhost:8000/v1/locations -H "Authorization: Bearer IL_TUO_TOKEN" -H "Content-Type: application/json" -d "{\"lat\":41.9028,\"lon\":12.4964,\"event_id\":1}"
   ```
4. Simula l'IVR che chiede lo stato:
   ```
   curl -X POST "http://localhost:8000/twilio/status?event_id=1"
   ```
   Riceverai l'XML con la frase che Twilio pronuncerebbe, indirizzo incluso.

---

## Passo 2 — Mettilo online (gratis, ~20 minuti)

Twilio deve poter raggiungere il server da internet. Il modo più semplice è
Render.com (piano gratuito).

1. Crea un account su https://github.com e uno su https://render.com
   (accedi a Render con il pulsante "Sign in with GitHub").
2. Su GitHub: **New repository** → nome `squillami-backend` → **uploading an
   existing file** → trascina TUTTI i file di questa cartella → Commit.
3. Su Render: **New → Web Service** → scegli il repository appena creato.
   - Runtime: **Docker** (rileva da solo il Dockerfile)
   - Instance type: **Free**
4. Nella sezione **Environment** aggiungi:
   - `SECRET_KEY` = una stringa lunga inventata da te (es. 40 caratteri a caso)
   - `TWILIO_AUTH_TOKEN` = lo aggiungerai al Passo 3
5. **Create Web Service**. Dopo qualche minuto avrai un indirizzo tipo
   `https://squillami-backend.onrender.com`. Verifica che
   `https://TUO-INDIRIZZO/health` risponda `{"status":"ok"}`.

> Nota: sul piano gratuito il server "si addormenta" dopo 15 minuti di
> inattività e la prima chiamata può impiegare ~40 secondi a svegliarlo.
> Per l'uso vero conviene il piano da 7 $/mese o Railway/Fly.io.

---

## Passo 3 — Collega Twilio (~15 minuti)

1. Crea un account su https://www.twilio.com/try-twilio (la prova è gratuita,
   con credito omaggio).
2. Nella Console: **Phone Numbers → Manage → Buy a number** → prendi il numero
   di prova gratuito che ti viene proposto.
3. Clicca sul numero → sezione **Voice Configuration**:
   - "A call comes in": **Webhook**
   - URL: `https://TUO-INDIRIZZO.onrender.com/twilio/voice`
   - Metodo: **HTTP POST**
   - Salva.
4. Torna alla home della Console e copia l'**Auth Token** (sezione Account
   Info) → incollalo su Render nella variabile `TWILIO_AUTH_TOKEN` → il
   servizio si riavvia da solo.
5. **Chiama il numero dal tuo telefono.** Sentirai la voce di Squillami che
   ti chiede il codice. Digita quello che hai registrato: nel log di Render
   (scheda Logs) vedrai la `PUSH SIMULATA`.

> Limiti dell'account di prova Twilio: prima della risposta sentirai un breve
> messaggio "trial account" (si salta premendo un tasto qualsiasi) e in alcuni
> casi il numero di prova è statunitense, quindi chiamarlo dall'Italia ha il
> costo di una chiamata internazionale. Con l'upgrade (~20 $ di ricarica)
> sparisce il messaggio e puoi prendere un numero europeo.

---

## Passo 4 — Push reali (quando costruiremo l'app)

1. Crea un progetto su https://console.firebase.google.com (gratis).
2. Impostazioni progetto → Account di servizio → **Genera nuova chiave
   privata** → scarica il file JSON.
3. Su Render: aggiungi il file come **Secret File** e imposta
   `GOOGLE_APPLICATION_CREDENTIALS` con il suo percorso.
4. Da quel momento la push arriva davvero al telefono con l'app installata.

---

## Struttura del progetto

```
app/main.py       ← tutte le API e i webhook Twilio (il cuore)
app/db.py         ← database SQLite (si crea da solo al primo avvio)
app/security.py   ← codici, token, verifica firma Twilio
app/push.py       ← invio push FCM (o simulazione se non configurato)
app/geocode.py    ← da coordinate a indirizzo (OpenStreetMap)
tests/            ← test automatici: python3 -m pytest tests/
```

## Cosa c'è già / cosa manca

Fatto: IVR con codice DTMF, squillo via push, attesa GPS in linea con
fallback sull'ultima posizione nota, indirizzo parlato, rate limiting,
verifica firma Twilio, storico eventi.

Prossimo passo: **l'app Android** (riceve la push, suona in silenzioso,
invia il GPS). Poi iOS, SMS con link mappa, app di onboarding.

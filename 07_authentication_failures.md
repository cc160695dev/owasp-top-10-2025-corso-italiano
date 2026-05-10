# A07:2025 — Errori di autenticazione (Authentication Failures)

> ✏️ **Rinominata** da *"Identification and Authentication Failures"* (2021). Il problema chiave: convincere un sistema che un attaccante è un utente legittimo. Coperture: **credential stuffing**, **brute force**, **password recovery deboli**, **MFA mancante**, **session management** debole.

---

## 1. Obiettivi (Learning Objectives)

Alla fine di questo modulo saprai:

- Distinguere **credential stuffing**, **brute force**, **password spraying** e **hybrid attack**.
- Implementare **MFA** correttamente (TOTP, WebAuthn/passkey, push verificato).
- Configurare politiche password conformi a **NIST 800-63B** (no rotazione obbligatoria, sì check delle "breached lists").
- Generare e invalidare sessioni in modo sicuro (post-login regen, logout, idle/absolute timeout, revoca refresh token).
- Difendere contro **account enumeration** e **credential exfiltration** durante la fase di registrazione/login/recovery.

---

## 2. Prerequisiti

- Hashing password con KDF → [04_cryptographic_failures.md §6](04_cryptographic_failures.md#6-codice-vulnerabile-vs-sicuro).
- Cookie e flag, JWT → [00_introduzione.md §5.4](00_introduzione.md#54-sessioni-cookie-e-jwt).
- Differenza autenticazione vs autorizzazione → [00_introduzione.md §5.5](00_introduzione.md#55-autenticazione-vs-autorizzazione).

---

## 3. Background OWASP

| Metrica | Valore |
|---------|--------|
| Posizione 2025 | **#7** (invariata) |
| CWE mappati | 36 |
| Max incidence rate | 15.80% |
| Avg incidence rate | 2.92% |
| Max coverage | **100.00%** |
| Total occurrences | 1.120.673 |
| Total CVE | 7.147 |

---

## 4. Descrizione (Description)

> *"Authentication failures occur when an attacker is able to trick a system into recognizing an invalid or incorrect user as legitimate."* — OWASP

### Sintomi tipici (sei vulnerabile se la tua app…)

- **Permette attacchi automatici** come **credential stuffing** (liste di `email:password` rubate altrove) o **hybrid password attacks** (`Password1!`, `Password2!`, `Password3!`).
- **Permette brute force** — non blocca/ritarda dopo X tentativi.
- **Accetta password deboli** — `admin/admin`, `Password1`, ecc.
- **Permette di registrarsi con credenziali già nei breach** (es. `haveibeenpwned`).
- **Recovery debole** — domande personali ("knowledge-based answers"), token recovery prevedibili o senza scadenza.
- **Storage password** in plaintext, "encrypted" (reversibile!) o con hash veloci/non salted.
- **MFA mancante o ineffective**, fallback deboli (es. recovery via SMS sostituibile).
- **Session ID nell'URL** o in campi nascosti, **non rigenerato dopo login** (vulnerabile a **session fixation**), **non invalidato a logout** o dopo periodo di inattività.
- **Audience/scope dei token non verificato** — JWT con `aud` o `iss` non controllati.

### Vocabolario degli attacchi

| Termine | Cos'è |
|---------|-------|
| **Brute force** | provare TUTTE le password possibili contro un singolo utente |
| **Credential stuffing** | provare combinazioni `email:password` rubate altrove (assume riuso) |
| **Password spraying** | provare *poche* password comuni contro **molti** account (evita lockout) |
| **Hybrid attack** | varia password note (`Winter2025` → `Winter2026`, incrementi prevedibili) |
| **Session fixation** | l'attaccante "fissa" un session ID prima del login e lo riusa dopo |
| **Account enumeration** | distinguere "utente esistente" da "non esistente" da risposte differenti |

### MFA — i fattori

Tre famiglie:

- **Qualcosa che SAI** — password, PIN.
- **Qualcosa che HAI** — phone, **TOTP authenticator** (Google Authenticator, Authy), **security key** (YubiKey, Titan), **passkey** (WebAuthn).
- **Qualcosa che SEI** — biometrica (impronta, volto).

> 🔑 **Concetto chiave:** "MFA" significa **almeno due fattori di tipo diverso**. Password + PIN = 1 fattore (entrambi "SAI"). Password + SMS = 2 fattori, ma SMS è **debole** (SIM swap). Password + TOTP è il minimo accettabile; **passkey/WebAuthn** è lo stato dell'arte (phishing-resistant).

---

## 5. Esempi di attacco (Example Attack Scenarios)

### Scenario #1 — Credential stuffing & password spray

> *"Credential stuffing, the use of lists of known username and password combinations, is now a very common attack. More recently attackers have been found to 'increment' or otherwise adjust passwords...changing 'Winter2025' to 'Winter2026', or 'ILoveMyDog6' to 'ILoveMyDog7'."* — OWASP

Sequenza:

1. L'attaccante scarica un breach dump (es. miliardi di righe `email:password`).
2. Filtra per il dominio email del target o usa il proxy per evitare rate limit.
3. Lancia un tool (`Sentry MBA`, `OpenBullet`) contro `/login`.
4. Anche con un tasso di successo dell'1%, su 1.000.000 di utenti sono **10.000 account compromessi**.

> Senza difese, l'app diventa un **password oracle** per validare le liste rubate.

### Scenario #2 — Single-factor authentication

> *"Most successful authentication attacks occur due to the continued use of passwords as the sole authentication factor."* — OWASP

Le vecchie best practice (rotazione obbligatoria, complessità *"Aa1!"*) hanno **incoraggiato** comportamenti deboli: riuso, password tipo `Estate2025!`, post-it sotto la tastiera. Risultato: la sola password è oggi insufficiente per qualunque applicazione che valga proteggere.

NIST ha **rovesciato** queste raccomandazioni (NIST 800-63B): no a rotazione automatica (solo on suspicion), sì a passphrase lunghe e a check contro breach.

### Scenario #3 — Logout e SSO

> *"A user uses a public computer to access an application and instead of selecting 'logout,' the user simply closes the browser tab and walks away."* — OWASP

L'utente chiude il tab → la **sessione resta valida** lato server. Poi un'altra persona apre il browser, riapre la cronologia, ed è **ancora dentro**.

Variante con **SSO**: la session di app1 è scaduta, ma quella IDP no, e Single Logout (SLO) non è configurato → l'attaccante naviga da un'app all'altra.

---

## 6. Codice vulnerabile vs sicuro

### Esempio A — Login con rate limit + lockout progressivo (Python/Flask)

❌ **Vulnerabile:**

```python
@app.post('/login')
def login():
    user = User.query.filter_by(email=request.form['email']).first()
    if user and user.password == request.form['password']:    # plain compare, e plaintext!
        session['uid'] = user.id
        return redirect('/dashboard')
    return 'Bad creds', 401
```

Problemi: comparison non costante, password in plaintext, no rate limit, no lockout, messaggio generico ma session ID non rigenerato.

✅ **Sicuro:**

```python
from flask_limiter import Limiter
from argon2 import PasswordHasher
from secrets import token_urlsafe

limiter = Limiter(key_func=lambda: f"{request.remote_addr}:{request.form.get('email','')}")
ph = PasswordHasher()

@app.post('/login')
@limiter.limit('5/minute; 20/hour')         # rate limit per IP+email
def login():
    email = request.form['email'].lower().strip()
    password = request.form['password']

    user = User.query.filter_by(email=email).first()
    valid = False
    if user:
        try:
            ph.verify(user.password_hash, password)
            valid = True
        except Exception:
            pass

    if not valid:
        log_failed_login(email, request.remote_addr)             # → A09
        return 'Invalid credentials', 401                          # stesso messaggio, sempre

    # post-login: rigenera session ID, MFA se attivo
    session.clear()
    session['uid'] = user.id
    session['session_id'] = token_urlsafe(32)
    if user.mfa_enabled:
        session['pending_mfa'] = True
        return redirect('/mfa')
    return redirect('/dashboard')
```

### Esempio B — TOTP (RFC 6238)

```python
import pyotp

# generazione del secret a enrollment
secret = pyotp.random_base32()
otpauth_url = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name='MyApp')
# mostra QR code da otpauth_url

# verifica al login
totp = pyotp.TOTP(secret)
if totp.verify(submitted_code, valid_window=1):
    # ok: code valido per ±30s
    ...
else:
    # rate limit anche qui!
    ...
```

### Esempio C — JWT con `aud`/`iss` validati

❌ **Vulnerabile:**

```python
import jwt
payload = jwt.decode(token, key=PUB, algorithms=['RS256'])    # niente aud/iss check
```

✅ **Sicuro:**

```python
payload = jwt.decode(
    token,
    key=PUB,
    algorithms=['RS256'],            # mai 'HS256' se firmate con chiave pubblica/privata
    audience='https://api.myapp.com',
    issuer='https://auth.myapp.com',
    options={'require': ['exp', 'aud', 'iss']},
)
```

⚠️ **Trappola:** accettare `alg: 'none'` o lasciare il JWT decode auto-detect dell'algoritmo è la **falla classica**. Specifica sempre `algorithms=['RS256']` (o quello che usi).

### Esempio D — Cookie di sessione

```http
Set-Cookie: SESSIONID=abc123...; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600
```

- `Secure` → solo via HTTPS.
- `HttpOnly` → JS non può leggerlo (mitiga furto via XSS).
- `SameSite=Lax` (o `Strict` per app sensibili) → mitiga CSRF.
- `Max-Age` ragionevole.

### Esempio E — Password breach check

```python
import hashlib, requests

def is_breached(password: str) -> bool:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    # k-Anonymity: si manda solo il prefisso, mai la password
    r = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=3)
    for line in r.text.splitlines():
        if line.startswith(suffix):
            return True
    return False
```

Da chiamare a **registrazione** e **change password**. Se `True`, rifiuta la password e spiega all'utente.

---

## 7. Come prevenirlo (How to Prevent)

Mitigazioni dirette OWASP, riformulate:

- **MFA ovunque possibile.** Specialmente per amministratori. Preferisci **passkey/WebAuthn**, poi TOTP, poi push autenticato. Evita SMS quando possibile.
- **Password manager-friendly.** Non bloccare paste; permetti spazi e long passphrase. NON deployare con default credentials.
- **No default credentials**, mai. Force-set della password al primo login degli admin.
- **Check di password deboli/breached** in registrazione e cambio password.
- **Politiche password allineate a NIST 800-63B**: passphrase lunghe (≥ 12-15 char), no rotazione automatica obbligatoria, no domande di sicurezza.
- **Anti-enumeration**: stesso messaggio per "user not found" e "password wrong"; stesso comportamento (timing) per registrazione/recovery; resti silente nel registrazione di un utente già esistente.
- **Rate limit progressivo**: ritardo crescente sui tentativi falliti. Attento a non causare DoS (lockout sull'account valido va combinato con captcha o sblocco automatico tempo-based).
- **Log e alert** (→ A09) per pattern di credential stuffing, brute force, account enumeration.
- **Session manager** server-side trusted: nuovo session ID **dopo login** (regen), entropia alta, in cookie sicuri, **non in URL**, invalidato a logout, idle e absolute timeout.
- **Sistema "comprato"** quando possibile: Auth0, Keycloak, Cognito, Okta, Azure AD B2C. Trasferisci il rischio dove sensato.
- **JWT**: valida `aud`, `iss`, `exp`, **scope** intesi. Mai `alg: none`. Brevi + refresh revocabili (vedi A01).
- **Protezione del flow di recovery**: token monouso, scadenza breve (15 min), invalidazione dopo use, **niente domande personali**, opzionalmente MFA aggiuntiva.

---

## 8. CWE rilevanti

| CWE | Nome |
|-----|------|
| **CWE-287** | Improper Authentication |
| **CWE-306** | Missing Authentication for Critical Function |
| **CWE-307** | Improper Restriction of Excessive Authentication Attempts (brute force) |
| **CWE-308** | Use of Single-factor Authentication |
| **CWE-384** | Session Fixation |
| **CWE-521** | Weak Password Requirements |
| **CWE-613** | Insufficient Session Expiration |
| **CWE-259** | Use of Hard-coded Password |
| **CWE-798** | Use of Hard-coded Credentials |
| **CWE-297** | Improper Validation of Certificate with Host Mismatch |

---

## 9. Lab pratico

### Lab consigliati

1. **PortSwigger Academy — Authentication**: <https://portswigger.net/web-security/authentication>. Inizia da *"Username enumeration via different responses"* poi *"Password reset broken logic"*, poi *"Brute-forcing a stay-logged-in cookie"*.
2. **PortSwigger Academy — JWT**: <https://portswigger.net/web-security/jwt>.
3. **OWASP Juice Shop** — sfide *"Login Admin"*, *"Reset Jim's Password"*, *"Easter Egg"*.
4. **HackTricks — Authentication bypass tricks**: <https://book.hacktricks.xyz/>.

### 🧪 Esercizio guidato — Aggiungi MFA a una web app

1. Parti da una mini-app Flask con login (vedi §6 Esempio A).
2. Aggiungi una tabella `mfa_secrets(user_id, secret, enabled_at)`.
3. Implementa un endpoint `POST /mfa/enroll`:
   - genera `secret = pyotp.random_base32()`,
   - mostra il QR code (con `qrcode` lib),
   - salva temporaneamente come "pending".
4. Implementa `POST /mfa/confirm` che chiede un codice TOTP per attivare il secret.
5. Modifica il login: dopo la password, se `user.mfa_enabled`, redirect a `/mfa` che chiede il codice.
6. Aggiungi rate limit anche su `/mfa` (es. 5/min).
7. Aggiungi i **recovery codes** (8 codici monouso, hashati nel DB).

✅ **Hai completato** se: hai un flow login → password → TOTP → dashboard, e hai testato che il login fallisce sia con password sbagliata che con TOTP sbagliato.

---

## 10. Quiz di autovalutazione

1. Differenza tra **brute force**, **credential stuffing** e **password spraying**?
2. Perché **NIST 800-63B** scoraggia la rotazione obbligatoria delle password?
3. **MFA via SMS**: perché è considerata più debole di TOTP/WebAuthn?
4. Cos'è **session fixation** e come si previene in 1 riga di codice?
5. Una login response che dice "*Email non registrata*" vs "*Password errata*": qual è il problema?
6. JWT **`alg: "none"`** — perché va sempre rifiutato?
7. Cosa è una **passkey** e perché è "phishing-resistant"?
8. Quando devi invalidare la sessione lato server?
9. Come implementeresti il **"non ricevuto, rimanda"** nel reset password evitando di trasformarlo in spam tool?

<details>
<summary>📖 Soluzioni</summary>

1. **Brute force**: tentare *tutte* le password contro **un** account. **Credential stuffing**: usare combinazioni `email:password` rubate altrove (assume riuso tra siti). **Password spraying**: tentare *poche* password (es. `Password1!`, `Welcome2025`) contro **molti** account, evitando i lockout per-account.
2. Perché in pratica gli utenti aggirano la rotazione con incrementi (`Estate2024 → Estate2025`) o riuso tra siti, peggiorando la sicurezza. Meglio una password lunga, mai breached, più MFA. Cambia solo se sospetti compromissione.
3. **SIM swap** (un attaccante convince l'operatore a trasferire il numero su una nuova SIM); **SS7 interception**; **phishing** "inserisci il codice ricevuto" combinato con AiTM proxy. SMS resta meglio di nulla, ma non è quello che si raccomanda per dati ad alto valore.
4. L'attaccante "fissa" il session ID prima del login (es. tramite link `?sid=...`) e poi, dopo che la vittima fa login, riusa lo stesso ID. Si previene **rigenerando il session ID al login** (`request.session.regenerate_id()` in molti framework, `session.clear()` + nuovo ID in Flask).
5. Permette **account enumeration**: l'attaccante distingue email registrate da non registrate, costruendo una lista per credential stuffing/phishing target. Si risolve con messaggio identico per ogni esito ("If the email exists, you'll receive instructions") e tempo di risposta uniforme.
6. Permette di **bypassare la firma**. Un attaccante prende un JWT, modifica il payload, mette `alg: "none"` e una signature vuota: se la libreria non controlla esplicitamente l'algoritmo, accetta. **Sempre specificare** la lista di algoritmi consentiti.
7. È una **credential FIDO2/WebAuthn** legata al dominio. Il device (telefono o security key) firma una challenge con la chiave privata; la chiave pubblica è registrata sul sito. Phishing-resistant perché il browser **lega la firma all'origine reale**: anche se l'utente è su `myapp-fake.com`, il device firma per `myapp-fake.com`, non per `myapp.com`, quindi il vero server rifiuta.
8. **Logout esplicito**, **idle timeout** (es. 30 min senza attività), **absolute timeout** (es. 12-24h), **change password** (invalida tutte le altre sessioni), **revoca esplicita** dell'admin.
9. Limita la frequenza per email (es. 1 ogni 60s, max 3/h). **Comunque rispondi sempre lo stesso** all'utente ("If the email exists you'll receive…"), e **logga** internamente. Aggiungi captcha dopo N richieste dallo stesso IP/sessione.

</details>

---

## 11. Cheat sheet — A07 in 60 secondi

- 🔑 **MFA ovunque**, preferisci **passkey/WebAuthn**, fallback TOTP, evita SMS.
- 🧂 **Password**: Argon2id + check contro breached lists (HIBP) + lunghezza > complessità + niente rotazione obbligatoria.
- 🚪 **Anti-enumeration**: messaggi e timing identici nei flussi di login/registrazione/recovery.
- ⏱️ **Rate limit** progressivo (per IP **e** per account) con backoff.
- 🔄 **Session**: nuovo ID al login (regen), cookie `Secure+HttpOnly+SameSite`, idle + absolute timeout, invalida a logout.
- 🪙 **JWT**: brevi, valida `alg`, `aud`, `iss`, `exp`. Refresh token revocabili.
- 🚫 Niente domande personali, niente default credentials, niente password manager-hostile UX.
- 📊 **Logga** ogni fail, allerta su pattern (→ A09).
- 🛒 Quando puoi, **compra l'auth** (Keycloak, Auth0, Cognito): meno superficie, meno bug.

---

## 12. Risorse e approfondimenti

- 🌐 [Pagina OWASP A07:2025](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)
- 📘 [OWASP Cheat Sheet — Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- 📘 [OWASP Cheat Sheet — Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- 📘 [OWASP Cheat Sheet — Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- 📘 [OWASP Cheat Sheet — Multifactor Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- 📘 [OWASP Cheat Sheet — JSON Web Token](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- 📖 [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) — Digital Identity / Authenticator
- 🔐 [WebAuthn / FIDO2](https://webauthn.guide/) — guida moderna a passkey
- 🛠️ [Have I Been Pwned — API](https://haveibeenpwned.com/API/v3) — check email/password
- 🛠️ [Keycloak](https://www.keycloak.org/), [Auth0](https://auth0.com/), [Authentik](https://goauthentik.io/) — IAM open-source/SaaS

---

⬅ Modulo precedente: [06_insecure_design.md](06_insecure_design.md)
➡ Prossimo: [08_software_or_data_integrity_failures.md](08_software_or_data_integrity_failures.md)

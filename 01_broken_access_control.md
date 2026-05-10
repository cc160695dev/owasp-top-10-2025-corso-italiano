# A01:2025 — Controllo degli accessi compromesso (Broken Access Control)

> 🥇 **#1 della Top 10:2025** — confermata in vetta. Il **100%** delle applicazioni testate ha avuto almeno una falla di access control. Il 94% delle app ha avuto qualche forma di violazione.

---

## 1. Obiettivi (Learning Objectives)

Alla fine di questo modulo saprai:

- Distinguere **autenticazione** (chi sei) da **autorizzazione** (cosa puoi fare) e capire perché solo la seconda è oggetto di A01.
- Riconoscere le 8 forme tipiche di Broken Access Control: **IDOR**, **forced browsing**, **parameter tampering**, **JWT manipulation**, **CORS misconfiguration**, **privilege escalation**, **CSRF**, **API senza controlli**.
- Scrivere e revisionare codice che applica i controlli **server-side**, in modalità **deny-by-default**.
- Eseguire un attacco IDOR su un lab e implementarne il fix.

---

## 2. Prerequisiti

- HTTP, sessioni, cookie, JWT → vedi [00_introduzione.md §5](00_introduzione.md#5-prerequisiti-tecnici-per-principianti).
- Differenza fra `401 Unauthorized` e `403 Forbidden`.
- Sapere come funzionano browser dev-tools (F12) e come modificare una request (es. con **curl** o **Burp Suite Community**).

---

## 3. Background OWASP

| Metrica | Valore |
|---------|--------|
| Posizione 2025 | **#1** (invariata dal 2021) |
| CWE mappati | 40 |
| Max incidence rate | **20.15%** |
| Avg incidence rate | 3.74% |
| Total occurrences | 1.839.701 |
| Total CVE | 32.654 |

> 📌 Cambiamento dal 2021: **SSRF** (Server-Side Request Forgery), che nel 2021 era una categoria a sé, è stato **assorbito** dentro A01 perché è di fatto un fallimento di controllo di accesso (l'app fa per conto dell'utente cose che l'utente non dovrebbe poter fare).

---

## 4. Descrizione (Description)

> *"Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification or destruction of all data, or performing a business function outside the user's limits."* — OWASP

In parole semplici: il **controllo degli accessi** è la regola che dice *"questo utente può fare quest'azione su questa risorsa?"*. Quando manca, è bucato, o si applica solo lato client, un attaccante può:

- **vedere** dati altrui,
- **modificare** o **cancellare** dati altrui,
- **eseguire** azioni riservate (es. operazioni admin, transazioni).

Le **8 forme tipiche** di Broken Access Control:

1. **Violazione del principio del minimo privilegio** (least privilege) → l'app dà permessi più larghi del necessario, invece di partire da "deny by default".
2. **Bypass del controllo** modificando URL, parametri, stato interno o HTML lato client (es. cambiare `?role=user` in `?role=admin`).
3. **Insecure Direct Object Reference (IDOR)** → puoi vedere/modificare l'account di altri cambiando un identificatore (es. `/account?id=42` → `/account?id=43`).
4. **API senza controlli** su `POST`, `PUT`, `DELETE` → il GET è protetto ma il DELETE no.
5. **Privilege escalation** → agire come utente senza essere loggato, o ottenere ruoli più alti del proprio (es. *user* → *admin*).
6. **Manipolazione di metadata** → replay/tamper di un **JWT**, di un cookie, di un campo nascosto; abuso del meccanismo di invalidazione JWT.
7. **CORS misconfiguration** → l'API risponde con `Access-Control-Allow-Origin: *` (o riflette qualsiasi origine) consentendo a siti di terzi di farsi servire dati sensibili.
8. **Forced browsing** → indovinare URL di pagine autenticate o admin (es. `/admin/`, `/internal/backup.zip`).

> 🔑 **Concetto chiave:** ogni risorsa privata deve essere protetta da un controllo di accesso **lato server**, valutato a ogni richiesta, **per quel utente specifico** e **per quella risorsa specifica**. La presenza di un controllo `if (user.role === 'admin')` solo nel frontend è zero protezione.

---

## 5. Esempi di attacco (Example Attack Scenarios)

### Scenario #1 — Parametro di account non verificato (IDOR)

L'app legge l'ID account dalla query string e lo inserisce in una query SQL **senza verificare** che appartenga all'utente loggato.

```http
GET /app/accountInfo?acct=12345 HTTP/1.1
Cookie: session=abc...
```

L'attaccante semplicemente cambia il parametro:

```http
GET /app/accountInfo?acct=99999 HTTP/1.1
Cookie: session=abc...
```

Risultato: vede l'account di un altro utente.

> ⚠️ **Trappola comune:** "tanto l'ID è un UUID lungo, non lo indovina mai". Falso: gli ID si scoprono spesso da URL condivisi, log, GitHub, Wayback Machine. **Anche se nessuno indovinasse l'ID**, manca il controllo: è una falla.

### Scenario #2 — Forced browsing su pagina admin

L'admin panel è raggiungibile a `https://example.com/app/admin_getappInfo` e gli sviluppatori si sono affidati al fatto che il link nel menu compare solo agli admin.

L'attaccante (utente normale) digita direttamente l'URL nel browser → la pagina si apre.

Variante più dannosa: la pagina è raggiungibile **anche senza autenticazione**.

### Scenario #3 — Solo controlli lato client

L'app ha controlli di autorizzazione **solo in JavaScript** (es. nasconde un bottone se non sei admin). Un attaccante salta del tutto il browser e chiama l'API direttamente:

```bash
curl https://example.com/app/admin_getappInfo \
  -H "Cookie: session=abc..."
```

Risposta: `200 OK` con i dati admin.

> 🔑 **Concetto chiave:** **i controlli lato client sono UX, non sicurezza.** Il client è sotto il controllo dell'attaccante: lui può modificare/disabilitare/saltare qualunque codice JS e chiamare le API direttamente.

---

## 6. Codice vulnerabile vs codice sicuro

### Esempio A — IDOR in Node.js / Express

❌ **Codice vulnerabile:**

```javascript
app.get('/api/orders/:orderId', requireAuth, async (req, res) => {
  const order = await db.orders.findOne({ id: req.params.orderId });
  res.json(order);
});
```

Il controllo `requireAuth` verifica solo che l'utente sia **loggato** (autenticazione), non che l'ordine **appartenga a lui** (autorizzazione).

✅ **Codice sicuro:**

```javascript
app.get('/api/orders/:orderId', requireAuth, async (req, res) => {
  const order = await db.orders.findOne({
    id: req.params.orderId,
    userId: req.user.id           // <-- ownership check server-side
  });
  if (!order) return res.status(404).end();   // 404, non 403, per non leakare l'esistenza
  res.json(order);
});
```

> 💡 **Buona pratica:** il filtro di ownership va nella **query stessa**, non in un `if` dopo aver letto l'ordine — così risparmi una query e azzeri il rischio di dimenticartelo.

### Esempio B — Privilege escalation in Python / Flask

❌ **Codice vulnerabile:**

```python
@app.route('/api/profile', methods=['POST'])
@login_required
def update_profile():
    data = request.get_json()
    user = current_user
    for field, value in data.items():
        setattr(user, field, value)   # mass assignment
    db.session.commit()
    return jsonify(user.to_dict())
```

L'attaccante invia `{"role": "admin"}` e diventa admin.

✅ **Codice sicuro:**

```python
ALLOWED_FIELDS = {'name', 'email', 'avatar_url'}

@app.route('/api/profile', methods=['POST'])
@login_required
def update_profile():
    data = request.get_json()
    user = current_user
    for field in ALLOWED_FIELDS & set(data.keys()):
        setattr(user, field, data[field])
    db.session.commit()
    return jsonify(user.to_dict())
```

### Esempio C — CORS rischioso

❌ **Vulnerabile:**

```python
@app.after_request
def add_cors(resp):
    resp.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    return resp
```

Riflette **qualsiasi origine** + permette le credenziali → un sito malevolo può fare richieste autenticate per conto dell'utente.

✅ **Sicuro:**

```python
ALLOWED_ORIGINS = {'https://app.example.com', 'https://admin.example.com'}

@app.after_request
def add_cors(resp):
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        resp.headers['Access-Control-Allow-Origin'] = origin
        resp.headers['Vary'] = 'Origin'
        resp.headers['Access-Control-Allow-Credentials'] = 'true'
    return resp
```

---

## 7. Come prevenirlo (How to Prevent)

Mitigazioni dirette dalla pagina OWASP, riformulate con esempi pratici:

1. **Server-side, sempre.** Tutti i controlli vanno **nel codice trusted del server o nelle serverless API** — mai (solo) nel client.
2. **Deny by default.** Eccetto le risorse pubbliche, parti dal "negato" e abilita esplicitamente. Nei framework: usa decoratori globali tipo `@require_role` invece di "ricordarsi" di aggiungerli su ogni endpoint.
3. **Riusa, non duplicare.** Implementa il meccanismo di access control **una volta sola** e riusalo (middleware, policy engine come **Casbin**/**OPA**). Minimizza l'uso di **CORS**.
4. **Modello basato sull'ownership.** Le query devono enforce `WHERE owner_id = :current_user`, non lasciar fare e poi controllare.
5. **Limiti di business.** Limiti come "max 5 trasferimenti al giorno" o "non puoi spostare più di X" devono vivere nel **dominio**, non nel frontend.
6. **Disabilita directory listing.** E assicurati che `.git`, `.env`, file di backup e simili **non** finiscano nella web root.
7. **Logga e allarma.** Logga tutti i fallimenti di access control. Allerta gli admin in caso di pattern (es. molti `403` consecutivi dallo stesso IP).
8. **Rate limiting.** Limita API e endpoint sensibili per ridurre l'impatto di tool automatici.
9. **Sessioni ben gestite.** Invalida le sessioni stateful sul server al logout. JWT stateless devono essere **brevi** (minuti, non giorni); per durate maggiori usa **refresh token** con possibilità di revoca (segui **OAuth 2.0 Token Revocation**).
10. **Toolkit collaudati.** Spring Security, Keycloak, AWS Cognito, Auth0, NextAuth, Casbin, OPA: usa qualcosa che è già stato attaccato e patchato da migliaia.
11. **Test funzionali.** Includi nei test **unit/integration** scenari di accesso negato (es. user A non vede dati di user B).

---

## 8. CWE rilevanti

> Lista completa: 40 CWE. Qui i più importanti per cominciare.

| CWE | Nome | Esempio |
|-----|------|---------|
| **CWE-284** | Improper Access Control | manca del tutto un controllo |
| **CWE-285** | Improper Authorization | controllo c'è ma sbaglia |
| **CWE-862** | Missing Authorization | endpoint completamente esposto |
| **CWE-863** | Incorrect Authorization | logica del controllo errata |
| **CWE-639** | Authorization Bypass Through User-Controlled Key | classico **IDOR** |
| **CWE-425** | Direct Request ('Forced Browsing') | URL nascosti raggiungibili |
| **CWE-352** | Cross-Site Request Forgery (CSRF) | azioni a nome dell'utente |
| **CWE-918** | Server-Side Request Forgery (SSRF) | (consolidato qui dal 2021) |
| **CWE-200/201** | Exposure of Sensitive Information | leakage di dati |

Definizioni complete: <https://cwe.mitre.org/>

---

## 9. Lab pratico

### 🧪 Lab consigliati (gratuiti)

1. **PortSwigger Web Security Academy — Access Control** (gratuito, account email):
   - <https://portswigger.net/web-security/access-control>
   - Inizia da: *"Unprotected admin functionality"* → poi *"User ID controlled by request parameter"* (IDOR classico) → poi *"User role controlled by request parameter"*.
2. **OWASP Juice Shop** (self-hosted, Docker o online):
   - <https://owasp.org/www-project-juice-shop/>
   - Cerca le sfide *"Admin Section"*, *"View Basket"*, *"Forgotten Sales"*.
3. **OWASP WebGoat** — modulo "Access Control Flaws".

### Esercizio guidato (IDOR)

Obiettivo: nel lab PortSwigger *"User ID controlled by request parameter"*:

1. Logga come `wiener:peter`.
2. Vai al tuo profilo e osserva la richiesta con dev-tools / Burp.
3. Identifica il parametro che identifica l'utente (es. `?id=wiener`).
4. Modifica in `?id=carlos`.
5. Recupera l'API key di `carlos` e completa la sfida.

✅ **Hai completato** se: hai rubato la chiave API di un altro utente solo cambiando un parametro.

### 🧪 Esercizio rapido in casa

Crea una mini-API Flask con due endpoint:
```
GET  /api/notes          # lista delle tue note
GET  /api/notes/<id>     # dettaglio di una nota
```
Inizialmente scrivila vulnerabile (filtro solo per ID, non per `user_id`). Poi crea due utenti e dimostrati a te stesso che da uno vedi le note dell'altro. Quindi applica il fix descritto in §6.

---

## 10. Quiz di autovalutazione

1. Qual è la differenza pratica tra **IDOR** e **forced browsing**?
2. Perché non basta nascondere il bottone "Admin" in JavaScript?
3. Cosa significa **deny by default**? Fai un esempio in un framework che conosci.
4. Un cookie `Set-Cookie: SESSIONID=abc; Secure; HttpOnly; SameSite=Strict` quale categoria di attacco aiuta a mitigare e come?
5. La query `SELECT * FROM orders WHERE id = :order_id` è abbastanza sicura per `GET /api/orders/<id>`? Se no, cosa ci aggiungi?
6. Perché OWASP raccomanda di tenere i **JWT stateless brevi** e usare i **refresh token** per durate maggiori?
7. Una API risponde con `Access-Control-Allow-Origin: *` e `Access-Control-Allow-Credentials: true`. Quale problema introduce?
8. Quando un utente non autorizzato accede a una risorsa altrui, è meglio rispondere `403` o `404`? Perché?

<details>
<summary>📖 Soluzioni</summary>

1. **IDOR**: l'URL/endpoint è "ufficiale" ma il parametro identifica una risorsa che non ti appartiene (es. cambi `id=42` → `id=43`). **Forced browsing**: l'URL stesso non dovresti conoscerlo / vederlo (es. `/admin`), e l'app si è limitata a non linkartelo invece di proteggerlo.
2. Perché il client è sotto il controllo dell'attaccante: può modificare il JS, disabilitarlo, oppure chiamare le API direttamente con curl/Burp. I controlli vanno fatti dove l'attaccante non arriva: il **server**.
3. Significa partire dal "tutto vietato" e abilitare esplicitamente. Esempio: in Spring Security, `http.authorizeRequests().anyRequest().authenticated()` — tutto richiede auth, e poi sblocchi le pagine pubbliche.
4. Mitiga: **`Secure`** evita che il cookie viaggi su HTTP in chiaro (MITM); **`HttpOnly`** impedisce a JS di leggerlo (furto via XSS); **`SameSite=Strict`** evita che il browser invii il cookie in richieste cross-site (CSRF). Le prime due sono A04, l'ultima è A01.
5. **No.** Manca il filtro di ownership: `... WHERE id = :order_id AND user_id = :current_user_id`. Senza, è IDOR.
6. Perché un JWT stateless una volta firmato è valido fino a scadenza: se viene rubato, non c'è modo facile di "revocarlo" (a meno di blacklist server-side, che vanifica il vantaggio dello stateless). Tenerlo breve riduce la finestra di abuso; il refresh token, gestito server-side, può essere revocato.
7. Permette a **qualsiasi sito** di fare richieste autenticate verso quell'API. È equivalente a togliere il controllo same-origin del browser. La combinazione `*` + `credentials: true` è in realtà bloccata dai browser moderni, ma si vede ancora con backend che riflettono dinamicamente l'`Origin` del richiedente: stesso effetto.
8. **`404`** è preferibile in molti casi, perché un `403` dice all'attaccante "esiste, ma non puoi". Un `404` ("non esiste") nasconde anche **l'esistenza** della risorsa, che a volte è già un'informazione sensibile (es. `/users/42 → 403` rivela che l'utente 42 esiste). Eccezione: se la policy è esplicita e tracciata, `403` può essere accettabile.

</details>

---

## 11. Cheat sheet — A01 in 60 secondi

- 🥇 **#1 della Top 10** — il 100% delle app testate ha avuto almeno un fail di access control.
- 🎭 È un fallimento di **autorizzazione**, non di autenticazione.
- 🛑 Solo controlli **server-side**, in modalità **deny-by-default**, con **ownership** nelle query (`WHERE user_id = :current_user`).
- 🚪 Le 8 forme da ricordare: **IDOR**, **forced browsing**, **parameter tampering**, **API senza controlli**, **privilege escalation**, **JWT manipulation**, **CORS aperto**, **CSRF**.
- 🔒 **JWT brevi** + refresh token revocabili. Mai accettare `alg: none`.
- 🚫 Mai (solo) controlli lato client.
- 📝 **Logga ogni fallimento** + rate limit sugli endpoint sensibili.

---

## 12. Risorse e approfondimenti

- 🌐 [Pagina OWASP A01:2025 ufficiale](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- 📘 [OWASP Cheat Sheet — Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- 📘 [OWASP Cheat Sheet — IDOR](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- 📘 [OWASP ASVS — Capitolo 4: Access Control](https://github.com/OWASP/ASVS)
- 📘 [OWASP API Security Top 10 — BOLA / BOPLA](https://owasp.org/API-Security/) (versione "API-only" di IDOR)
- 🛠️ [Casbin](https://casbin.org/) — libreria di policy engine multi-linguaggio
- 🛠️ [Open Policy Agent (OPA)](https://www.openpolicyagent.org/)
- 🧪 [PortSwigger — Access Control labs](https://portswigger.net/web-security/access-control)
- 📖 [RFC 7009 — OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)

---

➡️ Prossimo modulo: [02_security_misconfiguration.md →](02_security_misconfiguration.md)

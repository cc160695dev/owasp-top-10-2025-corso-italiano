# A10:2025 — Gestione errata delle condizioni eccezionali (Mishandling of Exceptional Conditions)

> ✨ **Categoria completamente nuova nel 2025.** Copre i tre fallimenti tipici nella gestione di errori, eccezioni, condizioni "anomale": **non li prevedi, non li riconosci quando accadono, non rispondi adeguatamente**. Risultato: crash, comportamenti inattesi, vulnerabilità (DoS, leak via errori, state corruption).

---

## 1. Obiettivi (Learning Objectives)

Alla fine di questo modulo saprai:

- Riconoscere le tre fasi del *mishandling*: prevenzione, detection, risposta.
- Implementare **error handling centralizzato** in un'app (Express/Flask/Spring).
- Capire cos'è il **fail-open** e perché OWASP raccomanda **fail-closed**.
- Gestire correttamente **race condition** e **transazioni distribuite** con rollback atomico.
- Applicare **rate limiting**, **quote** e **circuit breaker** per prevenire resource exhaustion.

---

## 2. Prerequisiti

- Concetto di **eccezione** in un linguaggio mainstream (try/catch, try/except).
- Concetto di **transazione DB** (ACID, commit/rollback).
- Aver letto [09_security_logging_and_alerting_failures.md](09_security_logging_and_alerting_failures.md) — A09 e A10 sono molto collegati.

---

## 3. Background OWASP

| Metrica | Valore |
|---------|--------|
| Posizione 2025 | **#10** ✨ (nuova) |
| CWE mappati | 24 |
| Max incidence rate | 20.67% |
| Avg incidence rate | 2.95% |
| Max coverage | **100.00%** |
| Total occurrences | 769.581 |
| Total CVE | 3.416 |

> 📌 **Perché nuova:** alcuni CWE erano sparsi tra varie categorie sotto l'etichetta vaga di "code quality". Erano sottovalutati. OWASP li ha **raggruppati** sotto un nome chiaro per dargli visibilità ed effettività di guidance.

---

## 4. Descrizione (Description)

> *"Mishandling exceptional conditions in software happens when programs fail to prevent, detect, and respond to unusual and unpredictable situations, which leads to crashes, unexpected behavior, and sometimes vulnerabilities."* — OWASP

### Tre fallimenti chiave

1. **Non prevenire** la condizione eccezionale (manca validation, manca rate limit).
2. **Non identificare** la condizione mentre accade (manca check di return value, manca catch).
3. **Rispondere male o non rispondere** (fail open, errore generico, leak di info, state corruption).

### Cause radice frequenti

- **Validation mancante / parziale**: input non validato, o validato solo lato client.
- **Error handling tardivo / "alto"**: try/catch grosso a livello di controller, mentre l'errore originale è perso (perché ricciato come eccezione generica) e il codice "dopo" continua come niente fosse.
- **Stati ambientali inattesi**: memoria, privilegi, network, file system. Se la `open()` fallisce ma il codice procede, possono succedere cose brutte.
- **Eccezioni non catturate** o catturate e ignorate (`except: pass` 🚨).
- **Inconsistenza** nel modo in cui le eccezioni sono gestite tra moduli: 5 librerie, 5 pattern.

### Impatti tipici

| Categoria | Esempi concreti |
|-----------|-----------------|
| **Logic bugs** | Coupon riscattato due volte per race condition |
| **Overflow / underflow** | Saldo `int32` che diventa negativo grandissimo |
| **Race condition** | Doppia spesa nel wallet |
| **Frodi finanziarie** | Transazione partita ma non finita → fondi "fantasma" |
| **Memory issues** | Heap leak, file descriptor leak che porta a DoS |
| **Privilege issues** | Eccezione durante `drop_privileges()` → si resta root |
| **Auth/authz** | Verifica password fallisce ma il flow di login prosegue (fail-open) |
| **Info disclosure** | Stack trace al client (cross-link con A02 e A04) |

### Concetti chiave

- **Fail-closed (fail-secure):** in caso di errore, **nega**. Default sicuro.
- **Fail-open:** in caso di errore, **consenti**. Default insicuro. Es. tipico: "se il check di permesso fallisce, considera ok per non bloccare l'utente". È il bug A10 per eccellenza.
- **Idempotency:** un'operazione idempotente, ripetuta più volte, produce lo stesso risultato. Critica per pagamenti, webhook, retry. Tipicamente con **idempotency key** = chiave unica del client che il server memorizza per riconoscere duplicati.
- **Atomicità delle transazioni:** o tutta la transazione si applica, o niente. Le DB lo offrono nativamente; le transazioni distribuite (es. multi-servizio) richiedono pattern come **saga** o **outbox**.

---

## 5. Esempi di attacco (Example Attack Scenarios)

### Scenario #1 — Resource exhaustion (DoS)

> *"Resource exhaustion via mishandling of exceptional conditions could be caused if the application catches exceptions when files are uploaded, but doesn't properly release resources after. Each new exception leaves resources locked or otherwise unavailable, until all resources are used up."* — OWASP

Tipico bug: handler che `open()` un file, l'upload fallisce, l'eccezione viene catturata, ma il file descriptor resta aperto. Dopo N upload falliti l'app raggiunge `EMFILE` (too many open files) e va giù.

Variante: connessioni DB non rilasciate, lock non liberati, thread stuck. **L'attaccante intenzionalmente forza errori** per saturare risorse.

### Scenario #2 — Sensitive data exposure via errori

> *"Sensitive data exposure via improper handling or database errors that reveals the full system error to the user. The attacker continues to force errors in order to use the sensitive system information to create a better SQL injection attack. The sensitive data in the user error messages are reconnaissance."* — OWASP

L'attaccante manda input "rotti" mirati (es. tipi sbagliati), riceve stack trace e messaggi DB completi (`Column "users.email" not found`). Ottiene gratis: schema, framework, versioni → costruisce attacchi più mirati (di solito injection, A05).

### Scenario #3 — State corruption nelle transazioni finanziarie

> *"State corruption in financial transactions could be caused by an attacker interrupting a multi-step transaction via network disruptions...debit user account, credit destination account, log transaction. If the system doesn't properly roll back the entire transaction (fail closed) when there is an error part way through, the attacker could potentially drain the user's account, or possibly a race condition that allows the attacker to send money to the destination multiple times."* — OWASP

Il classico double-spend. Senza atomicità, l'app si trova in uno stato **incoerente**: i soldi sono "usciti" ma "non arrivati" — o viceversa. L'attaccante sfrutta finestre di race per replicare la transazione.

---

## 6. Codice vulnerabile vs sicuro

### Esempio A — Risorsa non rilasciata (Python)

❌ **Vulnerabile:**

```python
def upload(file_path):
    f = open(file_path, 'rb')
    data = f.read()
    process(data)            # se solleva, f resta aperto
    f.close()
```

✅ **Sicuro:**

```python
def upload(file_path):
    with open(file_path, 'rb') as f:        # rilascio garantito
        data = f.read()
        process(data)
```

`with` (Python), `try-with-resources` (Java), `using` (.NET), `defer` (Go) — usali sempre.

### Esempio B — `except: pass` (Python)

❌ **Vulnerabile:**

```python
try:
    user = authenticate(token)
    is_admin = user.is_admin
except Exception:
    is_admin = True            # 🚨 fail-open di livello mondiale
```

Tipo bug che genera RCE, escalation, breach.

✅ **Sicuro:**

```python
try:
    user = authenticate(token)
except AuthError as e:
    logger.warning("auth failed", extra={"reason": str(e), "ip": request.remote_addr})
    abort(401)                 # fail-closed
is_admin = user.is_admin       # solo se l'auth è effettivamente passata
```

> 🔑 **Concetto chiave:** **mai catturare `Exception` generica** se non a livello di entry point con un handler che logga e fail-closed. Cattura **specifico** (es. `AuthError`, `IntegrityError`).

### Esempio C — Transazione atomica (Python + SQLAlchemy)

❌ **Vulnerabile:**

```python
def transfer(src, dst, amount):
    src.balance -= amount
    db.session.commit()                  # commit 1
    dst.balance += amount
    db.session.commit()                  # commit 2: se crasha, fondi persi
    audit_log(src, dst, amount)
```

✅ **Sicuro:**

```python
def transfer(src_id, dst_id, amount, idempotency_key):
    with db.session.begin():                                 # transazione unica
        # idempotency: se la chiave esiste già, ritorna l'esito precedente
        prev = db.session.query(IdempotencyRecord).filter_by(key=idempotency_key).one_or_none()
        if prev:
            return prev.result

        src = db.session.query(Account).with_for_update().get(src_id)   # row lock
        dst = db.session.query(Account).with_for_update().get(dst_id)
        if src.balance < amount:
            raise InsufficientFunds()
        src.balance -= amount
        dst.balance += amount
        db.session.add(IdempotencyRecord(key=idempotency_key, result='ok'))
        audit_log(src, dst, amount)
        # commit avviene all'uscita dal `with` se nessuna eccezione, altrimenti rollback
    return 'ok'
```

Caratteristiche: **transazione atomica**, **row lock** per prevenire race, **idempotency** lato server, **audit** dentro la transazione.

### Esempio D — Error handler centralizzato (Express)

❌ **Vulnerabile:**

```javascript
app.get('/users/:id', async (req, res) => {
  const user = await db.users.findById(req.params.id);
  res.json(user);                  // se findById solleva, va in default → stack trace
});
```

✅ **Sicuro:**

```javascript
app.get('/users/:id', async (req, res, next) => {
  try {
    const user = await db.users.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'not_found' });
    res.json(user);
  } catch (err) { next(err); }
});

// Handler centrale, ultimo middleware:
app.use((err, req, res, next) => {
  const id = req.id;
  logger.error({ err, request_id: id });           // server-side: tutto
  if (err.expose) {
    return res.status(err.status || 400).json({ error: err.code, request_id: id });
  }
  res.status(500).json({ error: 'internal_error', request_id: id });   // client: minimo
});
```

Vantaggi: **un solo posto** per la mappatura errore→risposta, log strutturato (A09), `request_id` per debugging, **niente stack al client**.

### Esempio E — Rate limit + circuit breaker

```javascript
// Rate limit
const rateLimit = require('express-rate-limit');
app.use('/api/', rateLimit({ windowMs: 60_000, max: 100 }));

// Circuit breaker su servizio downstream
const CircuitBreaker = require('opossum');
const breaker = new CircuitBreaker(fetchDownstream, {
  timeout: 3000, errorThresholdPercentage: 50, resetTimeout: 30000
});
breaker.fallback(() => ({ degraded: true }));
```

Se il downstream è in trouble, il breaker si **apre** e fallisce **fast** invece di accumulare richieste in coda — che porterebbero a resource exhaustion.

---

## 7. Come prevenirlo (How to Prevent)

OWASP, riformulato e organizzato:

### Architettura

- **Pianifica per l'eccezionale.** Aspettati il peggio: rete giù, DB lento, parser che esplode.
- **Catch dove l'errore avviene** (specifico), non in cima al controller con un Exception generico che maschera tutto.
- **Centralizza** la mappatura errore→risposta in **un solo posto** (un global exception handler).
- **Sempre fail closed.** Mai "se non sai, lascia passare".

### Recovery

- **Roll-back completo** delle transazioni iniziate. **Mai** tentare recovery parziale ("ho fatto solo metà, recupero il resto"): è la radice di errori irrecoverable.
- **Idempotency** sui write critical (pagamenti, webhook).
- **Atomicità** garantita dal DB; per multi-service usa **saga** o **outbox pattern**.

### Controlli sulle risorse

- **Rate limiting**, **quote**, **throttling**, **timeout**, **size limit** dovunque possibile. *"Niente in IT è illimitato"* — ogni risorsa illimitata è un DoS in attesa.
- **Circuit breaker** verso servizi esterni.
- **Connection pool** di dimensioni note + timeout. Idem per **thread pool**.
- **Cleanup garantito**: `with` / `try-with-resources` / `using` / `defer` / `finally`.

### Logging & risposta

- **Niente stack trace** o messaggi DB nella risposta client (A02/A04). Server-side log dettagliato; client-side minimal + `request_id`.
- **Deduplicazione** errori: se 5.000 volte la stessa cosa in un minuto, **statistica** invece di 5.000 righe.
- **Threat modeling** delle condizioni eccezionali (fa parte di A06).
- **Code review** per blocchi try/except sospetti.
- **Stress test** + chaos engineering (es. **Toxiproxy**, **gremlin**) per scoprire i fail-open.

---

## 8. CWE rilevanti

| CWE | Nome |
|-----|------|
| **CWE-209** | Generation of Error Message Containing Sensitive Information |
| **CWE-248** | Uncaught Exception |
| **CWE-252** | Unchecked Return Value |
| **CWE-274** | Improper Handling of Insufficient Privileges |
| **CWE-460** | Improper Cleanup on Thrown Exception |
| **CWE-476** | NULL Pointer Dereference |
| **CWE-550** | Server-generated Error Message Containing Sensitive Information |
| **CWE-636** | Not Failing Securely ('Failing Open') |
| **CWE-703** | Improper Check or Handling of Exceptional Conditions |

---

## 9. Lab pratico

### Lab consigliati

1. **PortSwigger Academy — Race conditions**: <https://portswigger.net/web-security/race-conditions> — lab moderni che mostrano single-packet race attacks (vedrai un coupon usato 10 volte, etc.).
2. **PortSwigger Academy — Information disclosure**: <https://portswigger.net/web-security/information-disclosure>.
3. **OWASP Juice Shop** — sfide *"Successful RCE DoS"*, *"Multiple Likes"*, *"Repetitive Registration"*.
4. **Toxiproxy** — <https://github.com/Shopify/toxiproxy>: inietta latenza/perdita di pacchetti tra app e DB, vedi cosa succede al tuo error handling.

### 🧪 Esercizio guidato — Race condition su coupon

1. Crea un endpoint Flask `POST /redeem` che:
   - cerca il coupon per code,
   - se `used == False`, segna `used = True` e applica lo sconto.
2. Rendi la query **non atomica** apposta.
3. Apri 50 richieste in parallelo con lo stesso code (es. con `vegeta` o un piccolo script asyncio).
4. Quante volte è stato applicato lo sconto?
5. Riscrivi con: transazione + `with_for_update()` (lock pessimistico), oppure `UPDATE ... WHERE used=false` con check di `rowcount` (atomic compare-and-set).
6. Rilancia il test: ora una sola riuscita.
7. (Bonus) Aggiungi una `idempotency_key` lato client.

✅ **Hai completato** se: hai *visto* lo sconto applicarsi N volte, capito perché, e visto la fix bloccarlo.

### 🧪 Esercizio rapido — Circuit breaker

In Node, scrivi una funzione che chiama un servizio esterno (es. `httpbin.org/status/500` per simulare errori). Osserva: con tante richieste, l'app si blocca. Aggiungi `opossum` come circuit breaker. Rilancia: sopra una soglia di errori, il breaker apre e fallisce immediatamente — l'app resta reattiva.

---

## 10. Quiz di autovalutazione

1. Definisci **fail-closed** vs **fail-open**, con un esempio per ciascuno.
2. Cosa succede in pratica quando si fa `except: pass` in un check di autorizzazione?
3. **Race condition** in un endpoint di pagamento: come la previeni a livello di DB?
4. Cosa è una **idempotency key** e in che scenario è critica?
5. **Saga pattern** vs **transazione DB locale**: quando usi quale?
6. Perché un'app non dovrebbe mai mostrare stack trace al client? In quale altra categoria OWASP cade questo?
7. Cosa è un **circuit breaker** e qual è il suo stato "*half-open*"?
8. Catturi `Exception` (generica) in cima al controller. È sempre sbagliato?
9. **NULL pointer dereference** è un problema solo dei linguaggi C-like? Argomenta.

<details>
<summary>📖 Soluzioni</summary>

1. **Fail-closed**: se un controllo fallisce, il sistema **nega** l'azione (default sicuro). Es: se il check authz solleva → 403. **Fail-open**: se fallisce, **consente**. Es: se il check authz solleva → si assume ok. Quasi sempre fail-closed è quello giusto; le eccezioni vanno **decise esplicitamente**, non capitare.
2. Si maschera **qualunque** errore — incluso un errore di login, di connessione DB, di token invalid — con un comportamento di "tutto ok". Tipicamente porta a **fail-open** completo: utenti diventano admin per default, dati sensibili leakati, ecc.
3. Tre tecniche: (a) **transazione + lock pessimistico** (`SELECT ... FOR UPDATE`); (b) **atomic compare-and-set** (`UPDATE ... WHERE state='pending'` + check `rowcount==1`); (c) **vincoli/unique** che impediscono il duplicato a livello DB. Spesso si combinano. Idempotency key in più protegge anche dai retry del client.
4. Una chiave generata dal client **prima** di un'operazione di scrittura non sicura da ripetere (pagamento, transfer). Il server la memorizza con il risultato; se la stessa key arriva di nuovo, **ritorna lo stesso risultato** senza riapplicare. Critico nei pagamenti/webhook con retry automatici.
5. **Transazione DB locale** quando tutta l'operazione è in **un solo DB**: usi ACID nativo. **Saga** quando più servizi sono coinvolti, ognuno con il suo DB: ogni step ha una **azione** e una **compensazione** (undo logico) e si concatenano. Più complessa ma necessaria per microservizi.
6. (a) Espone informazioni di reconnaissance (framework, versioni, schema, path interni); (b) può contenere segreti loggati per errore; (c) abilita attacchi più mirati. Cade primariamente in **A10**, ma anche in **A02** (configurazione di error handling sbagliata) e in **A04** (può leakare segreti).
7. Pattern che tutela un client da un dipendente in difficoltà: dopo N errori si **apre** (chiamate falliscono fast con fallback). Dopo un timeout, passa a **half-open**: lascia passare 1-2 chiamate di prova; se vanno bene **chiude** (normale), se falliscono torna **aperto**. Evita di affogare un servizio downstream già a terra.
8. Non sempre. Va bene **a livello di entry point** (es. global error handler), purché: (a) non maschera la decisione di sicurezza; (b) **logga** l'errore strutturato; (c) **fail-closed** verso il client (es. 500 generico). Sbagliato è catturare `Exception` *intorno* al check di sicurezza per "non rompere" l'esperienza utente.
9. **No, non solo C/C++.** In Java/C#/Python si chiama `NullPointerException`/`AttributeError`. In JS è `TypeError: Cannot read property X of undefined`. Sono runtime crash che possono diventare DoS, e — peggio — possono **bypassare check** ("se è null, considera l'utente come admin"). Linguaggi tipo Rust/Kotlin (null safety) li rendono compile-time error.

</details>

---

## 11. Cheat sheet — A10 in 60 secondi

- 🛑 **Fail closed** sempre. Mai "se non funziona, lascia passare".
- 🎯 Cattura **eccezioni specifiche**, mai `except Exception: pass`.
- 🔁 **Transazioni atomiche** + **idempotency key** sui write critical.
- 🧹 **Cleanup garantito**: `with` / `try-with-resources` / `using` / `defer`.
- ⏱️ **Rate limit, quote, timeout, size limit, circuit breaker** ovunque.
- 📦 **Niente illimitato**: connessioni, thread, code, file size, JSON depth.
- 🚫 **Niente stack trace** al client. Log dettagliato server-side + `request_id` minimal client.
- 🏛️ **Centralizza** error handling in un middleware/handler globale.
- 🧪 Testa con **chaos / fault injection** (Toxiproxy, gremlin) per scovare fail-open.
- 🪞 A10 collabora con **A06** (lo prevedi nel design) e **A09** (lo logghi quando accade).

---

## 12. Risorse e approfondimenti

- 🌐 [Pagina OWASP A10:2025](https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/)
- 📘 [OWASP Cheat Sheet — Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- 📘 [OWASP Cheat Sheet — Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- 🛠️ [Toxiproxy](https://github.com/Shopify/toxiproxy) — fault injection per integration testing
- 🛠️ [Opossum](https://nodeshift.dev/opossum/) — circuit breaker per Node
- 🛠️ [Resilience4j](https://resilience4j.readme.io/) — Java
- 🛠️ [Polly](https://github.com/App-vNext/Polly) — .NET
- 📖 [Microservices.io — Saga pattern](https://microservices.io/patterns/data/saga.html)
- 📖 [Stripe — Idempotent requests](https://stripe.com/docs/api/idempotent_requests) — design pattern di riferimento
- 📖 *Release It!* — Michael T. Nygard (libro classico su resilience patterns: bulkhead, timeout, circuit breaker)
- 🎯 [PortSwigger — Race conditions research](https://portswigger.net/research/smashing-the-state-machine)

---

⬅ Modulo precedente: [09_security_logging_and_alerting_failures.md](09_security_logging_and_alerting_failures.md)

🎉 **Hai finito i 10 moduli!** Vai al [99_glossario.md](99_glossario.md) per consolidare la terminologia, poi al [99_cheatsheet_finale.md](99_cheatsheet_finale.md) per la sintesi globale.

# A08:2025 — Errori di integrità di software o dati (Software or Data Integrity Failures)

> 🧬 La domanda chiave: *"come fa il sistema a sapere che il codice / i dati che sta per eseguire o usare **non sono stati alterati**?"* Quando la risposta è "*non lo sa*", siamo in A08.

---

## 1. Obiettivi (Learning Objectives)

Alla fine di questo modulo saprai:

- Definire l'**integrità** in security e distinguerla da confidenzialità e disponibilità (CIA).
- Capire **cos'è la deserializzazione insicura** e perché è uno dei vettori più potenti.
- Verificare l'integrità di package, container, update, configurazione.
- Distinguere **A08** dalla simile **A03** (supply chain): sovrappongono ma il focus è diverso.

---

## 2. Prerequisiti

- Concetto di **firma digitale** e **hash crittografico** (vedi [04_cryptographic_failures.md §4](04_cryptographic_failures.md#4-descrizione-description)).
- Concetto di **CI/CD** (toccato in [03_software_supply_chain_failures.md](03_software_supply_chain_failures.md)).
- Saper leggere un `package-lock.json` o equivalente.

---

## 3. Background OWASP

| Metrica | Valore |
|---------|--------|
| Posizione 2025 | **#8** (invariata) |
| CWE mappati | 14 |
| Max incidence rate | 8.98% |
| Avg incidence rate | 2.75% |
| Avg coverage | 45.49% |
| Total occurrences | 501.327 |
| Total CVE | 3.331 |

> 📌 **A08 vs A03** — entrambi toccano la fiducia nei componenti, ma:
> - **A03** = problemi di **supply chain** (chi fornisce, come si distribuisce, vendor compromessi).
> - **A08** = mancanza di **verifica di integrità** sui dati o sul software *al momento dell'uso* (firma, deserializzazione, integrità di update).
> Si sovrappongono (un attacco SolarWinds è sia A03 sia A08), ma la mitigazione è in posti diversi.

---

## 4. Descrizione (Description)

> *"Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations."* — OWASP

L'app è vulnerabile quando **tratta come trusted** codice o dati che sono **non verificati** o **manipolabili**.

### Quattro famiglie principali

1. **Untrusted dependencies / sources**
   *Plugin, librerie, moduli da repository non fidati o CDN non verificati.*
   Es.: includi `<script src="https://random-cdn/lib.js">` senza Subresource Integrity (SRI).

2. **CI/CD pipeline senza integrity check**
   *Build, packaging, release fatti senza firma né attestazione di provenance.*
   Es.: artefatti riusabili che chiunque con accesso all'agent CI può sostituire.

3. **Auto-update insicuro**
   *Update scaricati ed eseguiti senza verifica della firma del vendor.*
   Es.: app desktop che fa `wget update.bin && exec` senza controllare che `update.bin` sia firmato.

4. **Insecure deserialization**
   *Oggetti serializzati ricevuti dal client (cookie, header, body) e deserializzati come trusted.*
   Es.: cookie `auth=base64encoded(serializedPyObject)` che il server `pickle.loads()` senza verifica.

### Insecure deserialization in dettaglio

Linguaggi che hanno serializzazioni native pericolose: **Java** (`ObjectInputStream`), **Python** (`pickle`), **PHP** (`unserialize`), **.NET** (`BinaryFormatter`, `LosFormatter`). Una sola riga di codice può consentire **RCE** (Remote Code Execution) se l'input è attacker-controlled.

> 🔑 **Concetto chiave:** il serializzatore native ricostruisce **l'oggetto e i suoi metodi**, quindi può eseguire **codice** ad attacco. JSON/YAML semplice è più sicuro perché ricostruisce solo *dati*, non oggetti con metodi attivi (eccezione: YAML con tag tipo `!!python/object` → equivalente a pickle).

Difesa: **non deserializzare oggetti da fonti non fidate.** Se devi, usa formati dato-puri (JSON con schema strict, Protobuf), e firma/MAC il payload.

---

## 5. Esempi di attacco (Example Attack Scenarios)

### Scenario #1 — Insecure deserialization (cookie firma assente)

Un'app PHP serializza `User` e lo mette in cookie:

```
Cookie: user=O:4:"User":2:{s:5:"email";s:13:"a@example.com";s:5:"admin";b:0;}
```

L'attaccante intercetta, modifica `b:0` → `b:1`, e ora è admin. Senza MAC/firma del cookie, l'app non se ne accorge.

Variante peggiore: l'attaccante non solo modifica un campo, ma **sostituisce l'intera struttura** con un *gadget chain* che porta a RCE.

### Scenario #2 — Auto-update senza firma (esempio classico)

App desktop scarica updates da `http://updates.example.com/latest.exe` e li esegue. L'attaccante in MITM (Wi-Fi pubblico, DNS hijack) sostituisce il file con malware. Senza:

- HTTPS forzato + cert pinning,
- firma del binario verificata client-side,
- controllo della **versione** (rollback prevention),

l'utente diventa game-over.

### Scenario #3 — CI/CD pipeline manomesso

Branch protection assente; un attaccante con commit-rights modifica il workflow `.github/workflows/release.yml` per **firmare** un artefatto malevolo con la chiave del repo o per pubblicarlo su un registry. Il consumatore (ignaro) installa.

Variante: il **build cache** è condiviso e attacker-controllabile → un binario "trusted" è in realtà compilato da codice avvelenato.

### Scenario #4 — CDN script senza SRI

```html
<script src="https://cdn.example.com/lib/jquery.min.js"></script>
```

Se la CDN viene compromessa o il dominio scaduto, lo script servito può cambiare. Senza **Subresource Integrity** il browser non se ne accorge:

```html
<script src="https://cdn.example.com/lib/jquery.min.js"
        integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo"
        crossorigin="anonymous"></script>
```

---

## 6. Codice / config vulnerabili vs sicuri

### Esempio A — Python pickle (RCE via deserializzazione)

❌ **Vulnerabile:**

```python
import pickle, base64

@app.post('/restore')
def restore_session():
    blob = base64.b64decode(request.form['state'])
    state = pickle.loads(blob)               # 🚨 RCE se blob è ostile
    session.update(state)
```

Un payload pickle ostile esegue codice arbitrario: `os.system("rm -rf /")` o reverse shell.

✅ **Sicuro:**

```python
import json
from itsdangerous import URLSafeSerializer, BadSignature

signer = URLSafeSerializer(SECRET_KEY)

@app.post('/restore')
def restore_session():
    try:
        state = signer.loads(request.form['state'])      # JSON + HMAC
    except BadSignature:
        abort(400)
    if not isinstance(state, dict):                       # validazione di forma
        abort(400)
    session.update(state)
```

Cambiamenti: **JSON** (solo dati, nessuna istanziazione di classi), **firma HMAC** (l'attaccante non può modificare senza la chiave), validazione del **tipo**.

### Esempio B — Java deserializzazione

❌ **Vulnerabile:**

```java
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
SessionData data = (SessionData) ois.readObject();      // RCE classico (ysoserial)
```

✅ **Sicuro:**

- **Non** deserializzare oggetti da fonti non fidate. Usa JSON con Jackson/Gson e DTO espliciti.
- Se proprio devi: lookahead/filter (`ObjectInputFilter` da Java 9+), firmando il payload.

```java
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.SessionData;!*"          // allow-list di classi, deny per il resto
);
ois.setObjectInputFilter(filter);
```

### Esempio C — Subresource Integrity per script esterni

```html
<link rel="stylesheet"
      href="https://cdn.example.com/bootstrap.min.css"
      integrity="sha384-eOJMYsd53ii+scO/bJGFsiCZc+5NDVN2yr8+0RDqr0Ql0h+rP48ckxlpbzKgwra6"
      crossorigin="anonymous">
```

Se la risorsa cambia, il browser **rifiuta** di caricarla.

### Esempio D — `package-lock` integrity

Un `package-lock.json` ben formato include hash sha512 per ogni dipendenza:

```json
"node_modules/express": {
  "version": "4.21.0",
  "resolved": "https://registry.npmjs.org/express/-/express-4.21.0.tgz",
  "integrity": "sha512-..."
}
```

In CI, **`npm ci`** (non `npm install`) **verifica l'hash**. Una modifica al tarball viene rilevata.

### Esempio E — Cosign per firmare artefatti

```bash
# firma di un container image
cosign sign --key cosign.key registry.example.com/myapp:1.2.3

# verifica al deploy
cosign verify --key cosign.pub registry.example.com/myapp:1.2.3
```

Con **Sigstore keyless** (OIDC) puoi firmare senza gestire chiavi a lungo termine.

---

## 7. Come prevenirlo (How to Prevent)

Mitigazioni dirette OWASP, riformulate:

- **Firma digitale o equivalente** per verificare che software o dati arrivino dalla fonte attesa **e** non siano stati alterati. Tool: **cosign**, **Sigstore**, **GPG**, **Authenticode** (Windows), **codesign** (macOS).
- **Solo repository fidati** per librerie. Se possibile, **mirror interno** con allow-list.
- **Code review** per cambi di codice e configurazione (PR obbligatori, almeno una persona diversa che approva).
- **CI/CD pipeline ben separata, configurata, controllata**: vedi [03 §7.3](03_software_supply_chain_failures.md#73-hardening-dei-sistemi). Build immutabili, secrets per-environment, tamper-evident logs.
- **Niente deserializzazione** di dati non firmati / non cifrati ricevuti da client non fidati. Se devi:
  - usa formati dati puri (JSON, Protobuf),
  - firma il payload (HMAC, JWT firmato),
  - lookahead/allow-list delle classi (Java `ObjectInputFilter`),
  - **monitor** dei tentativi di deserializzazione fallita (segnale di attacco).
- **SBOM + verifica integrità** delle dipendenze: vedi A03.
- **SRI** per ogni risorsa esterna in HTML.
- **Auto-update** sempre via canale firmato (HTTPS + firma binario verificata + rollback prevention via versione monotona).
- **Rolling out staged**: limita il blast radius se viene compromesso un asset (vedi A03).

---

## 8. CWE rilevanti

| CWE | Nome |
|-----|------|
| **CWE-502** | Deserialization of Untrusted Data |
| **CWE-829** | Inclusion of Functionality from Untrusted Control Sphere |
| **CWE-830** | Inclusion of Web Functionality from an Untrusted Source |
| **CWE-494** | Download of Code Without Integrity Check |
| **CWE-345** | Insufficient Verification of Data Authenticity |
| **CWE-565** | Reliance on Cookies without Validation and Integrity Checking |
| **CWE-426** | Untrusted Search Path |
| **CWE-915** | Improperly Controlled Modification of Dynamically-Determined Object Attributes |

---

## 9. Lab pratico

### Lab consigliati

1. **PortSwigger Academy — Insecure Deserialization**: <https://portswigger.net/web-security/deserialization>. Lab in PHP, Java, Ruby — vedrai gadget chain reali.
2. **HackTricks — ysoserial**: <https://book.hacktricks.xyz/pentesting-web/deserialization>. Genera payload Java per testing.
3. **OWASP Juice Shop** — sfide *"Forged Coupon"*, *"Manipulate Basket"*.
4. **Sigstore tutorials**: <https://docs.sigstore.dev/> — firma il primo container.

### 🧪 Esercizio guidato — Cookie con firma HMAC

1. Scrivi un endpoint Flask `POST /set-prefs` che accetta JSON `{"theme":"dark","lang":"it"}` e lo salva in un cookie `prefs`.
2. Versione 1 (vulnerabile): salva il cookie come `base64(json)`. Da dev-tools, modifica e osserva che il server lo usa così com'è.
3. Versione 2 (sicura): usa `itsdangerous.URLSafeSerializer(SECRET).dumps(data)`.
4. Modifica di nuovo il cookie da dev-tools: il server ora **rifiuta**.
5. (Bonus) Esponi un endpoint `/restore` che ricostruisce un oggetto Python via `pickle` da input utente. Sviluppa il payload "ostile" con `pickle` e dimostralo (in lab!).
6. Sostituisci con `signer.loads()` su JSON. Il payload non funziona più.

✅ **Hai completato** se: hai visto un payload pickle eseguire codice nel tuo lab, e hai sperimentato in prima persona perché *non* va deserializzato input ostile.

> ⚠️ **Solo in lab tuo!** Non eseguire payload pickle su sistemi che non sono tuoi.

---

## 10. Quiz di autovalutazione

1. Spiega la differenza tra **A03** e **A08**.
2. Cos'è una **insecure deserialization** e perché può portare a RCE?
3. Cos'è un **gadget chain** in `ysoserial`?
4. Cosa fa l'attributo `integrity` in un `<script>`?
5. Come fai a sapere che un container `myapp:1.2.3` viene davvero da te?
6. Perché un cookie con dati serializzati lato client deve essere **firmato**, anche se è già criptato?
7. `pickle.loads(open('file.pkl').read())` su un file caricato dall'utente: vulnerabile? Perché?
8. **JSON** è sicuro da deserializzare? Cosa controlli comunque?
9. Cosa significa **rollback prevention** in un sistema di auto-update?

<details>
<summary>📖 Soluzioni</summary>

1. **A03** = la **provenienza/distribuzione** del software (chi è il vendor, è compromesso?, dipendenze, CI/CD). **A08** = la **verifica di integrità** quando si usano dati o software (firma, deserializzazione, SRI). Spesso si sovrappongono: SolarWinds è A03 *e* A08.
2. È quando un'app accetta una rappresentazione **serializzata** di un oggetto da una fonte non fidata e la "ricostruisce" via `pickle.loads`, `ObjectInputStream`, `unserialize`, `BinaryFormatter`. La ricostruzione **invoca metodi** dell'oggetto: con un payload preparato si forza l'esecuzione di codice arbitrario (RCE).
3. È una sequenza di chiamate fra classi/metodi presenti nel **classpath** dell'app target che, partendo da `readObject()`, arriva a una primitiva pericolosa (`Runtime.exec`, `ProcessBuilder`). `ysoserial` è un tool che genera payload pre-confezionati per gadget chain note (es. Apache Commons Collections, Spring).
4. Specifica un **hash atteso** della risorsa esterna (es. `sha384-...`). Il browser lo confronta con quanto scarica: se non corrisponde, **rifiuta**. Difende dai cambi (legittimi o malevoli) della CDN.
5. **Firma digitale** verificabile: con **cosign** + Sigstore puoi firmare l'image al build, e la pipeline di deploy verifica `cosign verify`. Combinato con SBOM, hai sia "ingredienti" sia "etichetta del produttore".
6. La cifratura nasconde il contenuto ma **non** garantisce che il client non lo abbia **modificato**. Servono entrambe (o cifratura **autenticata**, AEAD): un `User{admin:false}` cifrato senza autenticazione può essere bit-flippato per diventare `admin:true` se l'attaccante conosce la struttura.
7. **Sì, vulnerabile.** Pickle è documentato come pericoloso per input non fidato. Anche un file "innocuo" può contenere un payload. Se devi accettare upload da utente, leggilo come **bytes** e parsa con un formato dato-puro (JSON, MsgPack con strict mode).
8. Più sicuro perché ricostruisce **solo dati primitivi** (no metodi). Devi comunque controllare: **dimensione** (limita JSON max size), **profondità** (denial-of-service via JSON deeply nested), **schema** (i campi attesi hanno il tipo atteso, validazione con `pydantic`/`zod`/`ajv`).
9. Impedisce di "downgradare" a una versione più vecchia (potenzialmente vulnerabile). Si fa controllando una **versione monotonica** (numero o timestamp firmato): l'updater rifiuta update con versione ≤ corrente. Difesa contro attaccanti che, anche senza firmare, fanno servire una vecchia release vulnerabile.

</details>

---

## 11. Cheat sheet — A08 in 60 secondi

- 🧬 Mai deserializzare **oggetti** da input non fidato. Usa **JSON/Protobuf** + schema validation.
- ✍️ **Firma** ogni artefatto (container, binari, package): cosign/Sigstore, codesign, Authenticode.
- 🔗 **SRI** per ogni asset esterno (`<script integrity="sha384-...">`).
- 🍪 Cookie/JWT con **dati lato client**: sempre firmati (HMAC, JWS).
- 📥 Auto-update: HTTPS + firma + rollback prevention.
- 🔄 Lockfile + `npm ci` / `pip install --require-hashes` in CI.
- 🛡️ CI/CD: build immutabili, separation of duties, branch protection.
- 🚦 Staged rollout per limitare blast radius.
- 📊 Logga e allarma su deserializzazioni fallite, integrity mismatch (A09).
- 🪞 A08 e A03 sono **vicini**: trattali insieme per sistemi critici.

---

## 12. Risorse e approfondimenti

- 🌐 [Pagina OWASP A08:2025](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)
- 📘 [OWASP Cheat Sheet — Deserialization](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- 📘 [OWASP Cheat Sheet — Subresource Integrity](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html)
- 📘 [OWASP Software Component Verification Standard (SCVS)](https://owasp.org/www-project-software-component-verification-standard/)
- 🛠️ [Sigstore / cosign](https://www.sigstore.dev/) — firma keyless con OIDC
- 🛠️ [in-toto](https://in-toto.io/) — attestazioni di provenance
- 🛠️ [SLSA framework](https://slsa.dev/) — livelli di garanzia integrità
- 🛠️ [ysoserial](https://github.com/frohoff/ysoserial) — payload generator (research/test)
- 🛠️ [SRI Hash Generator](https://www.srihash.org/) — calcola hash per `integrity=`
- 📖 [Java ObjectInputFilter (JEP 290)](https://docs.oracle.com/javase/9/core/serialization-filtering1.htm)
- 📖 [Python pickle docs — security warning](https://docs.python.org/3/library/pickle.html)

---

⬅ Modulo precedente: [07_authentication_failures.md](07_authentication_failures.md)
➡ Prossimo: [09_security_logging_and_alerting_failures.md](09_security_logging_and_alerting_failures.md)

# 00 — Introduzione (Introduction)

> **In questo modulo:** capirai cos'è OWASP, come è stata costruita la Top 10 2025, cosa è cambiato dal 2021, e imparerai i prerequisiti tecnici di base (HTTP, sessioni, autenticazione, hashing) necessari per affrontare i 10 moduli successivi.

---

## 1. Obiettivi (Learning Objectives)

Alla fine di questa lezione saprai:

- Spiegare cos'è **OWASP** e a cosa serve la Top 10.
- Capire la differenza tra **CVE** e **CWE** e perché OWASP usa i CWE come unità di base.
- Distinguere **autenticazione** (chi sei) da **autorizzazione** (cosa puoi fare).
- Leggere una richiesta e una risposta **HTTP** e riconoscere i pezzi che useremo nei vari attacchi (URL, header, cookie, body, status code).
- Capire perché si usa **HTTPS/TLS** e cosa è un **cookie di sessione** o un **JWT**.
- Definire cos'è un **modello di minaccia** (threat model) — il modo di pensare alla sicurezza che useremo in tutto il corso.

---

## 2. Cos'è OWASP

**OWASP** sta per *Open Worldwide Application Security Project*. È una community globale, no-profit, che produce risorse gratuite (linee guida, tool, training) per aiutare sviluppatori e organizzazioni a costruire software più sicuro.

La risorsa più famosa di OWASP è la **Top 10**: una lista delle **10 categorie di rischio più critiche** per le applicazioni web. È giunta nell'edizione 2025 alla sua **8ª iterazione** (le precedenti: 2003, 2004, 2007, 2010, 2013, 2017, 2021, 2025).

> 🔑 **Concetto chiave:** la Top 10 OWASP **non** è una checklist esaustiva di tutti i bug possibili. È una **mappa dei rischi più diffusi e impattanti**, da usare come priorità minima nelle decisioni di security.

---

## 3. Metodologia 2025: come è stata costruita la lista

Per la Top 10 2025 OWASP ha analizzato:

| Numero | Significato |
|--------|-------------|
| **2.8 milioni** | applicazioni web testate |
| **13** | organizzazioni che hanno contribuito con dati (Veracode, Sonar, Semgrep, Contrast, Bugcrowd…) |
| **~175.000** | record CVE mappati a CWE (vs. 125.000 nel 2021) |
| **643** | CWE unici osservati (vs. 241 nel 2021) |
| **589** | CWE analizzati per la classificazione |
| **248** | CWE inclusi nelle 10 categorie finali |

L'approccio è **"data-informed", non "data-driven"**:

- 8 categorie su 10 vengono dai **dati** (frequenza, prevalenza, impatto).
- 2 categorie su 10 vengono dal **survey della community** di pratici. Questo perché alcune minacce emergenti non si vedono ancora nei dati storici (es. attacchi a CI/CD prima che diventassero noti).

Si misura **prevalenza, non frequenza**: che un'app abbia 4 o 4.000 istanze dello stesso bug conta uguale. Questo evita che strumenti automatici molto rumorosi distorcano la classifica rispetto a test manuali.

### CVE vs CWE

Sono i due acronimi che incontrerai ovunque, NON confonderli:

- **CVE** (*Common Vulnerabilities and Exposures*) → **una vulnerabilità specifica in un prodotto specifico**. Es. `CVE-2021-44228` = "Log4Shell", la vulnerabilità in Apache Log4j del 2021. Ogni CVE ha un ID univoco e una descrizione.
- **CWE** (*Common Weakness Enumeration*) → **una categoria/tipologia di debolezza** (la "famiglia"). Es. `CWE-89` = "SQL Injection". Migliaia di CVE diversi possono ricadere nello stesso CWE.

OWASP usa i **CWE** come unità di analisi perché sono trasversali a linguaggi e prodotti.

---

## 4. La Top 10:2025 in una tabella

| # | Categoria (EN) | Italiano | Note |
|---|----------------|----------|------|
| A01 | Broken Access Control | Controllo accessi compromesso | 100% delle app testate ha avuto un fail |
| A02 | Security Misconfiguration | Configurazione di sicurezza errata | ↑ dal #5 al #2 |
| A03 | Software Supply Chain Failures | Compromissione della catena di fornitura software | ✨ ampliata da "componenti vulnerabili" |
| A04 | Cryptographic Failures | Errori crittografici | ↓ dal #2 al #4 |
| A05 | Injection | Iniezione (SQLi, XSS, Command, LLM Prompt…) | ↓ dal #3 al #5; 62.445 CVE |
| A06 | Insecure Design | Design insicuro | ↓ dal #4 al #6 |
| A07 | Authentication Failures | Errori di autenticazione | rinominata (era "Identification & Authentication") |
| A08 | Software or Data Integrity Failures | Errori di integrità di software o dati | |
| A09 | Security Logging & Alerting Failures | Errori di logging e alerting | rinominata: focus nuovo su "alerting" |
| A10 | Mishandling of Exceptional Conditions | Gestione errata di condizioni eccezionali | ✨ **completamente nuova** |

### Cosa è cambiato dal 2021

- ✨ **Due categorie nuove (o profondamente cambiate):**
  - **A03** è stata espansa da "Vulnerable & Outdated Components" a una scope molto più ampia: **catena di fornitura software** (CI/CD, package npm/PyPI, attacchi tipo SolarWinds, worm Shai-Hulud).
  - **A10** è completamente nuova: gestione di errori, eccezioni, "fail-open", leak via messaggi di errore.
- 📉 **Cripto e Injection scendono**: non perché siano meno gravi, ma perché altre categorie sono cresciute di rilevanza.
- 📈 **Misconfiguration sale di tre posizioni**: è il riflesso di quanto cloud, container e microservizi abbiano moltiplicato i punti di configurazione.
- 🔁 **SSRF è stato consolidato dentro A01** (Broken Access Control).
- ✏️ **A07** è stata rinominata da *"Identification and Authentication Failures"* a *"Authentication Failures"*.
- ✏️ **A09** è stata rinominata da *"Security Logging and Monitoring Failures"* a *"Security Logging and Alerting Failures"*: il monitoraggio passivo non basta, serve **agire** sui segnali.

---

## 5. Prerequisiti tecnici per principianti

Se sei completamente nuovo allo sviluppo web, leggi tutta questa sezione. Se conosci già le basi, scorrila come ripasso.

### 5.1. Client e server: il modello a richiesta/risposta

Un'**applicazione web** è quasi sempre fatta di due parti:

- **Client** (di solito il **browser**): manda *richieste* (request).
- **Server**: riceve la richiesta, la elabora (eventualmente parlando con un database) e manda una *risposta* (response).

Il "linguaggio" di questa conversazione si chiama **HTTP** (HyperText Transfer Protocol).

### 5.2. Una richiesta HTTP, smontata pezzo per pezzo

Esempio: tu clicchi un link che apre `https://shop.example.com/account?id=42`. Il browser manda al server qualcosa di simile a:

```http
GET /account?id=42 HTTP/1.1
Host: shop.example.com
User-Agent: Mozilla/5.0 ...
Cookie: session=abc123xyz
Accept: text/html
```

I pezzi importanti per la sicurezza:

| Pezzo | Cos'è | Perché ci interessa |
|-------|-------|---------------------|
| **Metodo** (GET, POST, PUT, DELETE…) | Cosa vuole fare il client | Una API che permette `DELETE` senza autorizzazione è una falla A01 |
| **URL / path** (`/account`) | Quale risorsa | Si possono "indovinare" path nascosti (force browsing → A01) |
| **Query string** (`?id=42`) | Parametri leggibili nell'URL | Se cambi `42` in `43` accedi all'account altrui? IDOR (A01) |
| **Header** (es. `Cookie`, `Authorization`) | Metadati | I token di autenticazione viaggiano qui |
| **Body** (per POST/PUT) | Dati inviati | Form, JSON, file upload — qui passa la maggior parte degli input utente |

E la risposta:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: session=abc123xyz; HttpOnly; Secure

{"name": "Anna", "balance": 1500}
```

| Pezzo | Cos'è | Perché ci interessa |
|-------|-------|---------------------|
| **Status code** (200, 301, 401, 403, 404, 500…) | Esito | `401` = non autenticato; `403` = autenticato ma non autorizzato; `500` = errore server (può leakare info → A09/A10) |
| **Header di risposta** | Metadati | Header di sicurezza come `Strict-Transport-Security`, `Content-Security-Policy` mitigano molte categorie (A02, A04, A05) |
| **Body** | Contenuto | HTML, JSON, file… |

### 5.3. HTTPS, TLS e perché ci servono

- **HTTP** in chiaro: chiunque sia in mezzo alla rete (Wi-Fi pubblico, ISP, router compromesso) può **leggere** e **modificare** richieste e risposte.
- **HTTPS** = HTTP + **TLS** (*Transport Layer Security*, ex SSL): cifra il canale tra client e server.

TLS garantisce tre cose:

1. **Riservatezza** — un terzo non può leggere il traffico.
2. **Integrità** — un terzo non può modificarlo senza essere notato.
3. **Autenticazione del server** — il browser verifica un **certificato** firmato da una CA (autorità certificatrice) che attesta che `shop.example.com` è davvero quel server.

Senza HTTPS si aprono attacchi del tipo "**man-in-the-middle**" (MITM): vedi A04 — Cryptographic Failures.

### 5.4. Sessioni, cookie e JWT

HTTP è **stateless**: ogni richiesta è indipendente, il server non si "ricorda" automaticamente di te. Per ricordare che hai fatto il login si usano due tecniche principali:

#### Sessione lato server (con cookie)

1. Fai login → il server crea una **sessione** in memoria/database con un **session ID** casuale.
2. Il server ti manda quell'ID in un **cookie** (`Set-Cookie: session=abc123xyz`).
3. Da quel momento il browser allega automaticamente quel cookie a ogni richiesta verso quel sito.
4. Il server, ricevendo la richiesta, cerca `abc123xyz` nel suo store e capisce che sei tu.

I cookie hanno **flag di sicurezza** importantissimi:

- `Secure` → inviato solo via HTTPS.
- `HttpOnly` → JavaScript del browser non può leggerlo (mitiga il furto via XSS — A05).
- `SameSite` → controlla quando il browser invia il cookie a richieste cross-site (mitiga CSRF — A01).

#### JWT (JSON Web Token)

Un **JWT** è un token stateless: tutte le info sull'utente (chi è, ruoli, scadenza…) sono dentro il token stesso, **firmato** dal server.

Struttura: `header.payload.signature` — tre stringhe Base64 separate da punto.

Esempio (decodificato):

```json
// header
{ "alg": "HS256", "typ": "JWT" }

// payload
{ "sub": "user42", "role": "admin", "exp": 1736000000 }

// signature (binaria, verifica la firma)
```

⚠️ **Trappola comune (A01):** se accetti un JWT con `alg: "none"`, o non verifichi la firma, un attaccante si forgia il token che vuole. È un classico "**JWT manipulation**".

### 5.5. Autenticazione vs Autorizzazione

Termini facili da confondere ma con significato diverso:

| Concetto | Italiano | Domanda | Esempio di fallimento |
|----------|----------|---------|------------------------|
| **Authentication** | Autenticazione | *Chi sei?* | Password debole, MFA mancante (A07) |
| **Authorization** | Autorizzazione | *Cosa puoi fare?* | Utente normale che accede a `/admin` (A01) |

Sono **due controlli separati**: posso essere autenticato (so chi sei) ma non autorizzato (non puoi vedere quel dato).

### 5.6. Hashing e cifratura: NON sono la stessa cosa

- **Cifratura** (encryption): trasformazione **reversibile** con una chiave. Serve per *proteggere* dati in transito o a riposo, e poterli recuperare. Es. AES, RSA.
- **Hash**: funzione **a senso unico**. Da `"password123"` produce un digest tipo `ef92...`. Non si può tornare indietro. Serve a *verificare* (es. password) o a *identificare* in modo univoco (checksum di file).

⚠️ **Trappola comune (A04):** usare hash veloci come **MD5** o **SHA-1** per le password. Sono progettati per essere veloci, ma "veloce" significa che un attaccante con una GPU prova miliardi di combinazioni al secondo. Per le password si usano **funzioni di derivazione adattive** come **Argon2**, **bcrypt**, **scrypt**, **PBKDF2**, con un parametro di costo (work factor) e un **salt** per impedire le rainbow table.

### 5.7. Threat model: pensare come un attaccante

Quando progetti software in modo sicuro, il primo strumento è il **modello di minaccia**: rispondere a quattro domande prima di scrivere codice.

1. **Cosa sto costruendo?** (assets: dati personali, denaro, accessi…)
2. **Cosa può andare storto?** (minacce: chi attaccherebbe, perché, come?)
3. **Cosa farò al riguardo?** (mitigazioni)
4. **Ho fatto un buon lavoro?** (verifica)

Un metodo classico è **STRIDE** (Microsoft):

- **S**poofing → fingere di essere qualcun altro (→ A07)
- **T**ampering → modificare dati (→ A08)
- **R**epudiation → negare di aver fatto qualcosa (→ A09)
- **I**nformation disclosure → far trapelare dati (→ A04, A10)
- **D**enial of Service → rendere il sistema inutilizzabile (→ A10)
- **E**levation of privilege → diventare admin senza diritto (→ A01)

OWASP A06 — Insecure Design dedica un intero modulo a questa pratica.

---

## 6. Glossario veloce dei termini di base

Per il glossario completo vedi [99_glossario.md](99_glossario.md). Qui i termini essenziali per partire:

- **Vulnerabilità (vulnerability)** — un difetto che un attaccante può sfruttare.
- **Exploit** — il codice/tecnica che sfrutta una vulnerabilità.
- **Payload** — la "carica utile" di un exploit, cioè l'input malevolo specifico.
- **Attaccante (attacker / threat actor)** — chi cerca di violare il sistema.
- **Mitigation / countermeasure** — la difesa che annulla o riduce l'attacco.
- **Hardening** — irrigidimento delle configurazioni per ridurre la superficie d'attacco.
- **Least privilege** — principio: dai a ciascuno il minimo dei permessi necessari.
- **Defense in depth** — non affidarsi a una sola difesa; sovrapporne più.
- **CIA triad** — *Confidentiality, Integrity, Availability*: le tre proprietà che la sicurezza vuole preservare.
- **PII** (*Personally Identifiable Information*) — dati personali (nome, email, codice fiscale…).
- **PHI** (*Protected Health Information*) — dati sanitari.

---

## 7. Quiz di autovalutazione

Rispondi senza tornare indietro, poi controlla in fondo.

1. Qual è la differenza tra **CVE** e **CWE**?
2. Cosa significa che la Top 10 OWASP è **"data-informed" e non solo "data-driven"**?
3. Il flag **`HttpOnly`** sui cookie a cosa serve?
4. **MD5** può essere usato per hashare password? Perché sì o perché no?
5. Cosa risponde un server con status code **`403`** rispetto a `401`?
6. Quale categoria del 2025 è **completamente nuova** rispetto al 2021?
7. **Autenticazione** e **autorizzazione**: in una app, qual è il primo controllo a fallire se permetti a un utente normale di vedere `/admin`?
8. Nel framework **STRIDE**, a quale lettera corrisponde "**E**levation of privilege"? E in quale categoria OWASP cade tipicamente?

<details>
<summary>📖 Soluzioni</summary>

1. **CVE** identifica una vulnerabilità specifica in un prodotto specifico (es. CVE-2021-44228 = Log4Shell). **CWE** è una categoria di debolezza (es. CWE-89 = SQL Injection); molti CVE diversi possono mappare allo stesso CWE.
2. Significa che oltre ai dati statistici, OWASP integra l'opinione della community di pratici, perché i dati storici non catturano tutte le minacce emergenti.
3. Impedisce a JavaScript del browser (es. `document.cookie`) di leggere il cookie. Serve a mitigare il furto di cookie di sessione tramite **XSS** (A05).
4. **No.** MD5 è una funzione hash veloce e con collisioni note. Per le password serve una funzione adattiva, lenta e con salt: **Argon2**, **bcrypt**, **scrypt** o **PBKDF2** (vedi A04).
5. **`401 Unauthorized`** = "non so chi sei" (autenticazione mancante). **`403 Forbidden`** = "so chi sei, ma non puoi" (autorizzazione mancante). Confondere i due genera bug A01.
6. **A10 — Mishandling of Exceptional Conditions** è completamente nuova. Anche **A03 — Software Supply Chain Failures** è stata profondamente espansa.
7. L'**autorizzazione** (controllo dei permessi). L'autenticazione probabilmente ha funzionato (l'utente è loggato), ma il controllo "quest'utente può davvero accedere a `/admin`?" è mancato. È la radice di **A01 — Broken Access Control**.
8. La **E**. "Elevation of privilege" → tipicamente **A01 — Broken Access Control**.

</details>

---

## 8. Cheat sheet — In 60 secondi

- 🎯 **OWASP Top 10** = i 10 rischi web più critici per priorità di mitigazione.
- 📊 Edizione 2025 basata su **2.8M app, 175k CVE, 643 CWE**, "data-informed" + community survey.
- 🆕 Nuove/espanse: **A03** (supply chain) e **A10** (exceptional conditions).
- 🔑 **CVE** = vulnerabilità specifica; **CWE** = categoria di debolezza.
- 🛡️ Tre proprietà da difendere: **CIA** (Confidentiality, Integrity, Availability).
- 🎭 **Authentication** = chi sei; **Authorization** = cosa puoi fare. Sono controlli separati.
- 🔒 **HTTPS/TLS** è il minimo non negoziabile per dati in transito.
- 🍪 Cookie sicuri: sempre `Secure` + `HttpOnly` + `SameSite`.
- 🔐 Password = mai MD5/SHA1, sempre **Argon2/bcrypt/scrypt/PBKDF2** + salt.
- 🧠 Pensa con un **threat model** (es. **STRIDE**) prima di scrivere codice.

---

## 9. Risorse e approfondimenti

- 🌐 [OWASP Top 10:2025 — Introduzione ufficiale](https://owasp.org/Top10/2025/0x00_2025-Introduction/)
- 📘 [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) — riferimento per ogni categoria
- 📘 [OWASP ASVS (Application Security Verification Standard)](https://owasp.org/www-project-application-security-verification-standard/) — checklist dettagliata
- 📘 [OWASP Proactive Controls](https://owasp.org/www-project-proactive-controls/) — top 10 *cose da fare* (complementare alla top 10 *cose da evitare*)
- 🛠️ [PortSwigger Web Security Academy](https://portswigger.net/web-security) — lab gratuiti per ogni categoria
- 📖 [MITRE CWE List](https://cwe.mitre.org/) — definizioni ufficiali dei CWE
- 📖 [NVD — National Vulnerability Database](https://nvd.nist.gov/) — database CVE searchable
- 📚 *Threat Modeling: Designing for Security* — Adam Shostack (libro consigliato per A06)

---

🚀 **Pronto?** Vai al primo modulo: [01_broken_access_control.md →](01_broken_access_control.md)

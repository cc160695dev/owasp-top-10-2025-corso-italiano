# A06:2025 — Design insicuro (Insecure Design)

> 🏗️ **"Un design sicuro può ancora avere bug. Un design insicuro non può essere salvato da una implementazione perfetta."** Questa è la categoria più "filosofica" della Top 10: parla di **come si pensa il software prima di scriverlo**.

---

## 1. Obiettivi (Learning Objectives)

Alla fine di questo modulo saprai:

- Distinguere **design flaw** (manca un controllo) da **implementation defect** (controllo c'è ma è scritto male).
- Eseguire un **threat modeling** semplice (STRIDE) su un flusso applicativo.
- Riconoscere quando una **business logic flaw** è una vulnerabilità (anche senza "bug" tecnici).
- Integrare la sicurezza nel **Secure Development Lifecycle (SDLC)**: requirements → design → code → test → deploy → operate.

---

## 2. Prerequisiti

- Aver letto le sezioni *Threat Model* dell'intro: [00_introduzione.md §5.7](00_introduzione.md#57-threat-model-pensare-come-un-attaccante).
- Aver visto i moduli precedenti (A01-A05): A06 è il "perché" che sta dietro a molti dei sintomi visti nei moduli prima.

---

## 3. Background OWASP

| Metrica | Valore |
|---------|--------|
| Posizione 2025 | **#6** ⬇ (era #4) |
| CWE mappati | 39 |
| Max incidence rate | 22.18% |
| Avg incidence rate | 1.86% |
| Total occurrences | 729.882 |
| Total CVE | 7.647 |

> 📌 La diminuzione di posizione **non** indica che il problema sia minore: A02 (misconfig) e A03 (supply chain) sono saliti, "spingendo giù" A06 in classifica.

---

## 4. Descrizione (Description)

> *"Insecure design is a broad category representing different weaknesses, expressed as 'missing or ineffective control design.'"* — OWASP

### Differenza chiave: design vs implementation

OWASP è esplicito:

> *"There is a difference between insecure design and insecure implementation. We differentiate between design flaws and implementation defects for a reason: they have different root causes, take place at different times in the development process, and have different remediations."*

> *"A secure design can still have implementation defects leading to vulnerabilities that may be exploited. An insecure design cannot be fixed by a perfect implementation as needed security controls were never created to defend against specific attacks."*

| Aspetto | Insecure design (A06) | Implementation defect |
|---------|------------------------|------------------------|
| Cos'è | manca il **controllo** o è insufficiente come concetto | il controllo c'è ma è **codificato male** |
| Quando nasce | fase di **requirements/architettura** | fase di **codifica** |
| Esempio | sistema di password recovery basato su domande personali | filtro SQL scritto con concatenazione |
| Si trova con | **threat modeling**, design review, security stories | code review, SAST, DAST |
| Si risolve con | ridisegnare il flusso | fixare il codice |

> 🔑 **Concetto chiave:** se la **funzionalità di sicurezza giusta non era stata progettata**, nessuna implementazione perfetta la farà comparire. Es.: un sistema che non prevede MFA non diventa MFA-ready perché scrivi codice migliore.

### Causa radice

> *"One of the factors that contributes to insecure design is the lack of business risk profiling inherent in the software or system being developed."* — OWASP

Senza chiedersi *"quanto è critico questo flusso? quanto vale per un attaccante?"* non si capisce *quanta* sicurezza serve, e di conseguenza si dimensiona male (sotto o sopra).

### Le tre componenti

1. **Requirements & Resource Management** — i requisiti di sicurezza vanno raccolti come quelli funzionali, e bisogna allocare tempo/budget per la sicurezza.
2. **Secure Design** — design pattern sicuri, threat modeling, paved-road components.
3. **Secure Development Lifecycle (SDLC)** — la sicurezza è attività in **ogni fase**, non un controllo finale.

---

## 5. Esempi di attacco (Example Attack Scenarios)

### Scenario #1 — Credential recovery con domande di sicurezza

> *"A credential recovery workflow might include 'questions and answers,' which is prohibited by NIST 800-63b, the OWASP ASVS, and the OWASP Top 10. Questions and answers cannot be trusted as evidence of identity, as more than one person can know the answers."* — OWASP

Il flusso di recupero password chiede *"qual è il nome di tuo madre?"*, *"qual è la tua città di nascita?"*. Queste informazioni:

- Sono spesso **pubbliche** sui social.
- Sono uguali per **familiari** o persone vicine.
- Sono **statiche** nel tempo.

Non c'è "fix di codice" possibile: il **design** è sbagliato. Va riprogettato (es. email link + MFA fallback).

### Scenario #2 — Business logic flaw nelle prenotazioni

> *"A cinema chain allows group booking discounts and has a maximum of fifteen attendees before requiring a deposit. Attackers could threat model this flow and test if they can find an attack vector in the business logic of the application, e.g. booking six hundred seats and all cinemas at once in a few requests, causing a massive loss of income."* — OWASP

Tecnicamente nessuna validazione fallisce, nessun input malevolo. È il **modello di business** non difeso: niente cap su quante prenotazioni totali aperte, nessuna correlazione tra utente e numero di transazioni concorrenti, nessun deposit-on-suspicion.

> 💡 **Buona pratica:** ogni **limite di business** ("max 5 trasferimenti al giorno", "max 3 dispositivi") deve essere **enforced lato server** e **emergere dal threat modeling**, non essere un'aggiunta tardiva.

### Scenario #3 — Bot scalper

> *"A retail chain's e-commerce website does not have protection against bots run by scalpers buying high-end video cards to resell on auction websites."* — OWASP

L'app funziona "correttamente" — non c'è bug, non c'è injection. Ma il design non considera che **bot scriptati** possono comprare l'intero stock in millisecondi al lancio. Il problema è di **resilienza al traffico avversariale**.

Mitigazioni di design (non di codice puntuale): CAPTCHA contestuali, anti-bot fingerprinting (Cloudflare/Akamai), one-per-customer enforcement, queue/lottery design per drop limitati.

---

## 6. Esempi di "design vs implementazione"

Per chiarire la differenza, alcuni esempi:

### Caso A — Login

| Cosa | Tipo |
|------|------|
| Password salvate in MD5 | **implementation** (A04) — codice sbagliato |
| Login senza MFA né rate limit | **design** (A06) — il controllo non esiste |
| Login con MFA opzionale, rate limit, ma SQLi nel form | **implementation** (A05) |

### Caso B — Money transfer

| Cosa | Tipo |
|------|------|
| Manca conferma per importi sopra €5.000 | **design** (A06) |
| Conferma c'è, ma il token CSRF è prevedibile | **implementation** (A01/A05) |
| Conferma c'è e funziona, ma transazione non è atomica → race condition | **implementation** (A10) |

### Caso C — File upload

| Cosa | Tipo |
|------|------|
| Si accettano file `.exe` perché nessuno ha pensato all'allow-list | **design** (A06) |
| Allow-list MIME type implementata, ma controllata solo lato client | **implementation** (A01) |
| Allow-list server-side, ma non si controlla la **vera** firma del file | **implementation** (A05/A08) |

> 🔑 Il punto: **A06 ti chiede di porre la domanda giusta nella fase giusta**. Se nessuno ha mai chiesto *"l'utente potrebbe caricare un eseguibile?"*, il bug nasce a tavolino, non a tastiera.

---

## 7. Come prevenirlo (How to Prevent)

Mitigazioni dirette dalla pagina OWASP, riformulate:

1. **SDLC con AppSec.** Stabilisci e usa un **Secure Development Lifecycle**, con esperti AppSec che aiutano a valutare e progettare i controlli di sicurezza e privacy.
2. **Library di pattern sicuri / paved-road components.** Mantieni componenti già hardenati e standardizzati (es. un "AuthService" interno usato da tutti, non 5 implementazioni diverse).
3. **Threat modeling** delle parti critiche: autenticazione, access control, business logic, flussi di pagamento, gestione password. Strumenti: **STRIDE**, **PASTA**, **LINDDUN** (privacy), **Trike**.
4. **Threat modeling come strumento educativo.** Anche se non scrivi mai un documento "TM" formale, il *modo di pensare* va trasmesso al team.
5. **Security language** nelle user story:
   > *"Come utente, voglio cambiare password ed essere disconnesso da tutti gli altri device, **per evitare che un dispositivo compromesso continui ad accedere**"*.
6. **Plausibility check** a ogni livello: il frontend filtra, il backend riconvalida, il DB ha vincoli. Difesa in profondità.
7. **Unit & integration test** dei flussi critici **contro il threat model**: non solo "happy path", ma **misuse cases**.
8. **Segregation di tier** sul piano di sistema e di rete (DMZ, microservizi isolati, namespace) in funzione di esposizione e dato trattato.
9. **Tenant isolation** robusto — cruciale in SaaS multi-tenant. Mai assumere "stesso DB, query separata" come confine sufficiente.

### STRIDE in pratica — un piccolo esempio

Modello di un endpoint `POST /api/transfer`:

| STRIDE | Domanda | Mitigazione |
|--------|---------|-------------|
| **S**poofing | Posso impersonare un altro utente? | autenticazione robusta (A07), MFA, no token in URL |
| **T**ampering | Posso alterare l'importo in transito? | TLS, signed JWT, server-side validation |
| **R**epudiation | L'utente può negare? | audit log immutabile (A09) |
| **I**nformation disclosure | La risposta perde info? | risposta minima, no stack trace (A04/A10) |
| **D**oS | Posso saturarli? | rate limit, quota, idempotency (A10) |
| **E**levation of privilege | Posso pagare *dal* conto altrui? | ownership check (A01), confirm step |

Questa tabella, fatta **prima** di scrivere il codice, evita 6 categorie di bug.

---

## 8. CWE rilevanti

| CWE | Nome |
|-----|------|
| **CWE-256** | Unprotected Storage of Credentials |
| **CWE-269** | Improper Privilege Management |
| **CWE-311** | Missing Encryption of Sensitive Data |
| **CWE-312** | Cleartext Storage of Sensitive Information |
| **CWE-362** | Race Condition |
| **CWE-434** | Unrestricted Upload of File with Dangerous Type |
| **CWE-501** | Trust Boundary Violation |
| **CWE-522** | Insufficiently Protected Credentials |
| **CWE-807** | Reliance on Untrusted Inputs in a Security Decision |
| **CWE-841** | Improper Enforcement of Behavioral Workflow |

---

## 9. Lab pratico

### Lab consigliati

1. **PortSwigger Academy — Business Logic Vulnerabilities**: <https://portswigger.net/web-security/logic-flaws> — il lab più diretto per A06.
2. **OWASP Threat Dragon** (free tool di threat modeling) — <https://owasp.org/www-project-threat-dragon/>: prova a modellare un'app reale.
3. **OWASP Cornucopia** — gioco di carte (anche online) per fare threat modeling in modo collaborativo: <https://owasp.org/www-project-cornucopia/>.
4. **Microsoft Threat Modeling Tool** (Windows): tool storico, gratuito.

### 🧪 Esercizio guidato — Threat model di un endpoint reale

Scegli un endpoint di un progetto che conosci (o questo: `POST /api/coupon/redeem` di un ipotetico e-commerce, body: `{"code": "..."}`).

1. Disegna un mini-diagramma: client → API → DB.
2. Per ogni lettera di **STRIDE**, scrivi una minaccia plausibile.
3. Per ogni minaccia, scrivi *una* mitigazione concreta (codice o config).
4. Confronta con la tua attuale implementazione: quante mitigazioni mancano?
5. Pensa a una "**misuse case**": "*come attaccante, voglio riscattare lo stesso coupon 1000 volte in parallelo*". Cosa fai per impedirlo? (idempotency key, lock pessimistico, atomic decrement).

✅ **Hai completato** se: sei uscito con almeno **3 mitigazioni mancanti** e hai capito che il bug "race condition sul redeem" è un design issue, non un bug di codice.

---

## 10. Quiz di autovalutazione

1. Spiega in due righe la differenza tra **insecure design** e **implementation defect**.
2. Se un'app non ha MFA, è A06 o A07?
3. Cosa è **STRIDE**? Cita due lettere e a cosa corrispondono.
4. Perché le **domande di sicurezza** ("nome del cane") sono considerate insecure design?
5. Una **race condition** in un endpoint di pagamento dove si scala da A06 ad A10? Da chi è "colpa"?
6. Cosa è una **misuse case** e in che modo differisce da una user story classica?
7. **"Tenant isolation by query filter"** in un SaaS multi-tenant: è un design abbastanza forte? Argomenta.
8. Se un security expert ti dice *"abbiamo implementato CSP e HSTS"* ma manca il threat modeling sui flussi di money-transfer, in quale categoria è la falla principale?

<details>
<summary>📖 Soluzioni</summary>

1. **Insecure design** = il controllo *non è stato pensato*: nessuna implementazione lo riempirà. **Implementation defect** = il controllo è stato pensato ma codificato male: si fixa nel codice.
2. **A06.** È un controllo **mancante** (di design). Se MFA c'è ma è bypassabile (es. token prevedibile), allora A07 (implementazione di un controllo di autenticazione che fallisce).
3. *Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege*. Es.: **S** = fingere di essere un altro (autenticazione/identità); **T** = alterare dati in transito o a riposo (integrità).
4. Perché si basano su informazioni **non segrete** (spesso pubbliche, deducibili o note a familiari) e **statiche**. Non rispettano la definizione di "fattore di autenticazione" (qualcosa che solo tu sai/hai/sei). NIST 800-63B le vieta.
5. La **race condition** è A10 — *Mishandling of Exceptional Conditions* (gestione errata di concorrenza/condizioni inattese). La **mancanza dell'idempotency** o di transazioni atomiche è un design issue (A06): se fin dall'inizio nessuno aveva pensato "questo flusso può essere chiamato 1000 volte in parallelo?", il design è insicuro. Spesso entrambe coesistono.
6. Una **misuse case** descrive cosa farebbe **un attaccante** (o un utente malevolo) con il sistema, non un utente legittimo. È complementare alle user story positive: *"come attaccante, posso ripetere il login N volte e bloccare l'account di un utente?"*.
7. **No.** Va bene come *prima* difesa, ma l'isolamento per query filter dipende da: ogni endpoint che ricorda di mettere `WHERE tenant_id = ?` (un solo `forgot` apre un cross-tenant), nessuna funzione admin che bypassa il filtro, nessuna join che salta il filtro. Modelli più robusti: schema separati per tenant, DB separati, **row-level security** del DB enforced sotto.
8. **A06.** I controlli di transport (CSP, HSTS) sono difese trasversali (A02/A04) ma non sostituiscono il design specifico del dominio "money transfer" (limiti, conferma forte, audit, idempotency, anti-fraud).

</details>

---

## 11. Cheat sheet — A06 in 60 secondi

- 🏗️ **A06 = controllo mancante per design**, non controllo scritto male.
- 🧠 **Threat modeling** è lo strumento principe: usa **STRIDE** in 30 minuti su ogni flusso critico.
- 📚 Mantieni una **paved road**: componenti standard sicuri ("AuthService", "FileUploadService") riusati ovunque.
- ✍️ Scrivi **misuse cases**, non solo user stories.
- 🔐 **Limiti di business** (max trasferimenti, max device, deposito) sono **server-side** e **enforced**.
- 🧪 Test di sicurezza vanno **co-scritti** col codice, non aggiunti dopo.
- 🔁 **Difesa in profondità**: anche se la prima barriera fallisce, le successive contengono il danno.
- 📋 ASVS / NIST 800-63B / OWASP SAMM come reference: non reinventare i requirements.
- 🤝 **AppSec coinvolto in design review**, non solo in test finale.
- 🚦 **No "knowledge-based" recovery** (domande personali). Email link + MFA.

---

## 12. Risorse e approfondimenti

- 🌐 [Pagina OWASP A06:2025](https://owasp.org/Top10/2025/A06_2025-Insecure_Design/)
- 📘 [OWASP SAMM (Software Assurance Maturity Model)](https://owaspsamm.org/) — framework SDLC
- 📘 [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) — checklist requisiti
- 📘 [OWASP Cheat Sheet — Threat Modeling](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- 🛠️ [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/) — tool free, web-based
- 🛠️ [Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool)
- 🛠️ [OWASP Cornucopia](https://owasp.org/www-project-cornucopia/) — gioco per threat modeling collaborativo
- 📖 [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) — Digital Identity
- 📖 *Threat Modeling: Designing for Security* — Adam Shostack (libro consigliato)
- 📖 *Securing DevOps* — Julien Vehent
- 🎥 [LINDDUN](https://linddun.org/) — threat modeling **per la privacy**

---

⬅ Modulo precedente: [05_injection.md](05_injection.md)
➡ Prossimo: [07_authentication_failures.md](07_authentication_failures.md)

# 99 — Cheat Sheet finale & Checklist deploy-ready

> Sintesi globale del corso. Stampabile, da tenere a portata. Non sostituisce i moduli — li riassume.

---

## 1. Le 10 categorie in una tabella

| # | Categoria | Sintomo tipico | UNA difesa-chiave |
|---|-----------|----------------|--------------------|
| **A01** | [Broken Access Control](01_broken_access_control.md) | Cambio `id=42→id=43` e vedi dati altrui | Ownership server-side: `WHERE user_id = :current_user` + deny by default |
| **A02** | [Security Misconfiguration](02_security_misconfiguration.md) | Stack trace, default password, header mancanti | Hardening **automatizzato e ripetibile** + Mozilla Observatory |
| **A03** | [Software Supply Chain Failures](03_software_supply_chain_failures.md) | Dipendenza compromessa, CI/CD bucato | **SBOM + scanner continuo + firma artefatti** |
| **A04** | [Cryptographic Failures](04_cryptographic_failures.md) | MD5 sulle password, TLS < 1.2 | **Argon2id** per password + **TLS 1.3** + AEAD |
| **A05** | [Injection](05_injection.md) | `' OR '1'='1`, `<script>`, `; cat /etc/passwd` | **Query parametrizzate** + **CSP** + escape context-aware |
| **A06** | [Insecure Design](06_insecure_design.md) | Manca un controllo necessario, non un bug nel codice | **Threat modeling (STRIDE)** prima di codificare |
| **A07** | [Authentication Failures](07_authentication_failures.md) | Brute force/cred stuffing senza limiti, no MFA | **MFA (passkey > TOTP > SMS)** + rate limit + breached-password check |
| **A08** | [Software/Data Integrity Failures](08_software_or_data_integrity_failures.md) | `pickle.loads(user_input)`, no SRI, no firma | **Mai deserializzare oggetti ostili** + firmare artefatti |
| **A09** | [Security Logging & Alerting](09_security_logging_and_alerting_failures.md) | Breach scoperto da terzi, log scarsi | **Logging strutturato** + SIEM + use case di **alerting** |
| **A10** | [Mishandling of Exceptional Conditions](10_mishandling_of_exceptional_conditions.md) | `except: pass`, race condition, fail-open | **Fail-closed** + transazioni atomiche + idempotency + rate limit |

---

## 2. Mappa categorie ↔ tool / standard

### Standard/framework di riferimento

- **OWASP ASVS** — checklist requisiti
- **OWASP Proactive Controls** — top 10 *cose da fare*
- **OWASP SAMM** — maturity model SDLC
- **NIST 800-53 / 800-63B / 800-61** — controlli, identità, IR
- **CIS Benchmarks** — hardening
- **PCI DSS** — pagamenti
- **SLSA** — supply chain integrity

### Tool consigliati per categoria

| Tipo di tool | Categoria principale | Esempi |
|--------------|----------------------|--------|
| **SAST** (analisi statica) | A05, A06, A10 | Semgrep, CodeQL, SonarQube |
| **DAST** (test dinamici) | A01, A05 | OWASP ZAP, Burp Suite |
| **SCA** (composition analysis) | A03, A08 | Dependency-Track, Snyk, Trivy, `npm audit`, `pip-audit` |
| **Secrets scanner** | A02, A03, A04 | gitleaks, trufflehog, GitHub secret scanning |
| **IaC scanner** | A02 | Checkov, KICS, tfsec |
| **Container scanner** | A02, A03 | Trivy, grype, Clair |
| **Cloud posture (CSPM)** | A02 | ScoutSuite, Prowler, AWS Security Hub |
| **Header / TLS audit** | A02, A04 | Mozilla Observatory, SSL Labs, testssl.sh |
| **Signing** | A03, A08 | cosign / Sigstore, Authenticode |
| **WAF** | A05 (secondary) | ModSecurity + CRS, Cloudflare, AWS WAF |
| **SIEM / logging** | A09 | Loki+Grafana, Elastic, Splunk, Wazuh |
| **Threat modeling** | A06 | OWASP Threat Dragon, MS Threat Modeling Tool |

---

## 3. Checklist "Pre-Deploy" (deploy-ready)

Da rispondere ✅ **prima** di mettere qualunque cosa in produzione. Se anche una sola è ❌, fermati.

### Identità & accesso (A01, A07)

- [ ] Tutti gli endpoint privati richiedono auth (deny-by-default).
- [ ] Tutti i controlli di autorizzazione sono **server-side** (mai solo JS).
- [ ] Le query critiche includono `WHERE user_id = :current_user` (ownership).
- [ ] **MFA** disponibile (e obbligatorio per admin).
- [ ] Password store con **Argon2id / bcrypt / scrypt / PBKDF2-HMAC-SHA-512** + salt.
- [ ] **Check breached password** (HIBP) a registrazione e change.
- [ ] **Rate limit** progressivo su `/login`, `/register`, `/forgot-password`.
- [ ] Session ID **rigenerato dopo login**, invalidato a logout/idle/absolute.
- [ ] Cookie sensibili: `Secure` + `HttpOnly` + `SameSite`.
- [ ] JWT: `alg`/`aud`/`iss`/`exp` validati. Mai `alg: none`.

### Configurazione & deploy (A02)

- [ ] **Niente default credentials**.
- [ ] **Niente debug / sample app / Actuator pubblici** in prod.
- [ ] Header HTTP: HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- [ ] **Mozilla Observatory** ≥ B+.
- [ ] Bucket / blob storage: **block public access** + encryption at rest.
- [ ] IAM least-privilege; secrets in vault/KMS, **mai** in repo.
- [ ] Niente `X-Powered-By`/`Server` con versione esposta.

### Supply chain & integrità (A03, A08)

- [ ] **SBOM** generato per ogni build (CycloneDX / SPDX).
- [ ] **SCA continuo**: scanner CI fa fail su `high`/`critical` non triaged.
- [ ] Lockfile committato; CI usa `npm ci` / `pip install --require-hashes`.
- [ ] `ignore-scripts` in CI (npm), abilita selettivamente.
- [ ] Artefatti **firmati** (cosign / Sigstore / Authenticode).
- [ ] CI/CD: `permissions:` minimi, secrets scoped, branch protection, 2-person review.
- [ ] **Niente deserializzazione** di oggetti da input non fidato.
- [ ] **SRI** per ogni `<script>`/`<link>` esterno.

### Cripto (A04)

- [ ] **TLS ≥ 1.2** (preferibilmente 1.3) con cipher FS (ECDHE).
- [ ] **HSTS** preload-ready.
- [ ] Algoritmi: AES-GCM / ChaCha20-Poly1305. **No** MD5, SHA-1, ECB, CBC nei nuovi design.
- [ ] **Random crittografico** per token, IV, salt (`crypto.randomBytes` / `secrets`).
- [ ] Chiavi sensibili in **HSM/KMS**.
- [ ] Niente segreti hardcoded / committati (gitleaks pulito).
- [ ] **Validazione certificato** server (no `verify=False`).

### Input & output (A05, A02)

- [ ] **Query parametrizzate** ovunque (no concatenazione).
- [ ] **Template auto-escaping** per output HTML.
- [ ] **CSP** restrittiva (no `'unsafe-inline'`, no `'unsafe-eval'` se possibile).
- [ ] Comandi shell: `execFile`/`spawn` con args separati, mai `exec` con stringa.
- [ ] **Schema validation** input (zod/pydantic/ajv) con `strict`.
- [ ] **Limiti** su size body, file upload, JSON depth, query params.

### Design & business logic (A06)

- [ ] **Threat model** scritto (anche minimo) per i flussi sensibili.
- [ ] **Misuse case** considerati (non solo happy path).
- [ ] Limiti di business **enforced server-side** (max trasferimenti, max device, ecc.).
- [ ] **Recovery flow** sicuro: token monouso, scadenza breve, no domande personali.
- [ ] **Tenant isolation** verificato (cross-tenant test).
- [ ] **Bot/anti-abuse** considerato dove vale (CAPTCHA, fingerprint).

### Logging & alerting (A09)

- [ ] **Logging strutturato** (JSON) con livello, timestamp, request_id.
- [ ] **Eventi loggati**: login success/fail, access control fail, transazioni alte, cambi privilegi.
- [ ] **Niente sensitive nei log**: password, token, OTP, PAN/CVV, PII estesa.
- [ ] **Forwarding centrale** a SIEM con storage append-only/WORM.
- [ ] **Alerting use case** definiti (credential stuffing, exfiltration, privilege escalation).
- [ ] **Playbook IR** scritto (almeno uno per le 3 detection più probabili).
- [ ] **Honeytoken** piazzati dove sensato.

### Resilienza (A10)

- [ ] **Fail-closed** in tutti i check di sicurezza.
- [ ] **Niente `except: pass`** o `catch (Exception _) { }` muti.
- [ ] **Transazioni atomiche** per operazioni critiche; **idempotency key** per write retry.
- [ ] **Cleanup garantito** (`with`, `try-with-resources`, `using`, `defer`).
- [ ] **Rate limit** + **timeout** + **circuit breaker** verso dipendenze esterne.
- [ ] **Niente stack trace** in risposta client.
- [ ] **Error handler centrale** con `request_id` per correlazione.
- [ ] **Limit** ovunque: connection pool, thread pool, body size, file size, JSON depth.

---

## 4. Workflow consigliato di adoption

Se la tua org parte da zero, **non** affrontare le 10 categorie in parallelo. Ordine pragmatico:

1. **A01** + **A07**: protezione dell'accesso (auth/authz). È il bersaglio #1 degli attacchi.
2. **A04**: cripto basica (TLS, password storage, HSTS). Velocissimo da fixare, alto ROI.
3. **A02**: hardening (header, default cred, IAM, secrets in vault). Quick win.
4. **A05**: injection — code review + ORM + CSP + WAF come safety net.
5. **A03**: supply chain — SBOM + scanner continuo. Ti scopre rischi accumulati.
6. **A09**: logging strutturato + alerting. Senza visibilità, non sai se sei attaccato.
7. **A10**: error handling, fail-closed, idempotency. Si fa man mano sui flussi critici.
8. **A08**: integrità — SRI, firme, blocco deserializzazione ostile.
9. **A06**: threat modeling — è il livello "mature" che permea il resto.

---

## 5. Anti-pattern memorizzabili (le cose che fanno tutti e che fanno male)

| ❌ Anti-pattern | Perché è male | Cosa fare |
|----------------|---------------|-----------|
| Controllo authz solo lato client (JS che nasconde un bottone) | Il client è dell'attaccante | Server-side, sempre |
| `WHERE id = ?` senza `AND user_id = ?` | IDOR | Filtro di ownership nella query |
| `SELECT * FROM x WHERE name = '${input}'` | SQLi | Prepared statement |
| `MD5(password)` o `SHA-256(password)` | Veloce → crackabile | **Argon2id** + salt |
| `Math.random()` per token | Predicibile | `crypto.randomBytes` |
| `except Exception: pass` | Maschera tutto, fail-open | Cattura specifico, log, fail-closed |
| `pickle.loads(user_input)` | RCE | JSON + schema |
| `exec("cmd " + input)` | Command injection | `execFile` con args |
| `Set-Cookie: id=X` (senza flag) | XSS theft, CSRF | `Secure; HttpOnly; SameSite` |
| Stack trace al client in prod | Reconnaissance gratuita | Errori generici + log lato server |
| `npm install` in CI | Non deterministico, può tirare nuovo malware | `npm ci` + lockfile |
| Default credentials (admin/admin) | Trovati in 30 secondi | Disabilita / forza-cambio al primo login |
| Storing JWT in `localStorage` | Leggibile da JS → XSS theft | Cookie `HttpOnly` o memoria volatile |
| 1 sola password come fattore | Credential stuffing | **MFA** (preferibile passkey) |
| Bucket S3 "public-read" | Data leak in 1 click | Block Public Access + IAM esplicito |
| Log con password/token | Leak nel SIEM | **Redact** + non loggare segreti |
| `alg: "none"` in JWT | Bypass firma | Specifica `algorithms=['RS256']` |

---

## 6. La regola dei 5 minuti

Quando qualcuno ti propone un nuovo flusso, applica **STRIDE in 5 minuti**:

> Per ogni lettera, una minaccia plausibile + una mitigazione.

| Lettera | Domanda |
|---------|---------|
| **S**poofing | Posso fingermi un altro? Auth/MFA copre? |
| **T**ampering | Posso alterare dati in transito o a riposo? TLS, signed payload, integrity check? |
| **R**epudiation | L'utente può negare? Audit log immodificabile? |
| **I**nformation disclosure | Risposte/log/errori leakano info? |
| **D**oS | Saturazione, race, illimitati? Rate limit, quota, timeout, circuit breaker? |
| **E**levation | Privilege escalation? Ownership check, deny-by-default? |

Se passa STRIDE, non hai costruito un sistema sicuro — ma hai eliminato i 6 errori più comuni.

---

## 7. Mantra finali

- 🛡️ **Defense in depth**, sempre. Non affidarti a una sola difesa.
- 🚪 **Deny by default**, non allow.
- 🔚 **Fail closed**, non open.
- 👥 **Server-side**, non client-side.
- 🔑 **Least privilege**, ovunque.
- 📐 **Standard testati**, non cripto/auth fatti in casa.
- 👀 **Logga e allerta**, sennò non sai.
- 🧠 **Threat modeling** prima del codice, non dopo.
- ⚡ **Aggiorna in fretta**, ma deliberatamente, con SBOM.
- 🤝 **Comprare l'auth/IAM** quando puoi, non costruirla.

---

## 8. Risorse master

Le risorse "definitive" che vale la pena salvare in segnalibro:

- 🌐 [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
- 📘 [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) — un cheatsheet per ogni argomento
- 📘 [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) — checklist requisiti
- 📘 [OWASP Proactive Controls](https://owasp.org/www-project-proactive-controls/) — top 10 *cose da fare*
- 📘 [OWASP SAMM](https://owaspsamm.org/) — maturity model
- 🛠️ [PortSwigger Web Security Academy](https://portswigger.net/web-security) — i lab di riferimento
- 📖 [MITRE CWE](https://cwe.mitre.org/) e [MITRE ATT&CK](https://attack.mitre.org/)
- 📖 [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- 📖 [haveibeenpwned](https://haveibeenpwned.com/) — breach notifications

---

⬅ Torna al [README](README.md) · 📚 [Glossario](99_glossario.md) · 🚀 [00_introduzione.md](00_introduzione.md)

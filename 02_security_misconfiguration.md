# A02:2025 — Configurazione di sicurezza errata (Security Misconfiguration)

> 📈 **Salita dal #5 al #2** — il riflesso diretto di quanti più "punti di configurazione" hanno cloud, container, microservizi e CI/CD.

---

## 1. Obiettivi (Learning Objectives)

Alla fine di questo modulo saprai:

- Capire cosa rende vulnerabile una configurazione (di server, framework, cloud, container).
- Identificare le **default credential**, i **debug mode** lasciati attivi e gli **header di sicurezza** mancanti.
- Saper costruire un processo di **hardening** ripetibile e automatizzato.
- Configurare gli header di sicurezza essenziali in un'app web.

---

## 2. Prerequisiti

- HTTP, header e status code → [00_introduzione.md §5.2](00_introduzione.md#52-una-richiesta-http-smontata-pezzo-per-pezzo).
- Cookie e flag (`Secure`, `HttpOnly`, `SameSite`) → [00_introduzione.md §5.4](00_introduzione.md#54-sessioni-cookie-e-jwt).
- Concetto di **least privilege** e **hardening** dal glossario.

---

## 3. Background OWASP

| Metrica | Valore |
|---------|--------|
| Posizione 2025 | **#2** ⬆ (era #5) |
| CWE mappati | 16 |
| Max incidence rate | **27.70%** (la più alta della Top 10!) |
| Avg incidence rate | 3.00% |
| Total occurrences | 719.084 |
| Total CVE | 1.375 |

> 📌 È la categoria con la **massima incidenza singola** (27.70%). Tradotto: nelle app testate, è la falla più probabile da trovare.

---

## 4. Descrizione (Description)

> *"Security misconfiguration occurs when a system, application, or cloud service is set up incorrectly from a security perspective, creating vulnerabilities."* — OWASP

Un'applicazione è vulnerabile quando presenta una o più di queste condizioni:

1. **Hardening mancante** in qualunque parte dello stack (OS, web server, app server, DB, framework, cloud).
2. **Permessi cloud impostati male** (es. bucket S3 pubblico, IAM troppo permissivo).
3. **Funzionalità inutili abilitate** (porte, servizi, account, framework di test, esempi, documentazione).
4. **Account default attivi** con password mai cambiate (`admin/admin`, `root/root`).
5. **Errori che leakano informazioni** sensibili: stack trace completi, versioni del framework, path interni.
6. **Funzionalità di sicurezza disabilitate** dopo upgrade — il classico "abbiamo aggiornato e qualcosa si era spento".
7. **Backwards-compatibility** prioritizzata rispetto alla configurazione sicura (es. supporto a TLS vecchi, cipher deboli).
8. **Setting insicuri** in server, framework, librerie, DB.
9. **Header di sicurezza mancanti** o con valori insicuri.

> 🔑 **Concetto chiave:** A02 colpisce raramente *una sola cosa*. È quasi sempre l'**accumulo** di piccole sviste: debug mode + Spring Boot Actuator pubblico + IAM permissivo + account default. Singolarmente "innocui", insieme spalancano la porta.

### Header di sicurezza essenziali (memorizza questi)

| Header | A che serve |
|--------|-------------|
| `Strict-Transport-Security` (**HSTS**) | Forza HTTPS, evita downgrade attack (A04) |
| `Content-Security-Policy` (**CSP**) | Limita da quali origini caricare risorse → mitiga **XSS** (A05) |
| `X-Content-Type-Options: nosniff` | Impedisce MIME sniffing del browser |
| `X-Frame-Options` o `Content-Security-Policy: frame-ancestors` | Mitiga **clickjacking** |
| `Referrer-Policy: no-referrer-when-downgrade` (o più stretto) | Limita info nel `Referer` |
| `Permissions-Policy` | Controlla API browser (camera, geolocation…) |

---

## 5. Esempi di attacco (Example Attack Scenarios)

### Scenario #1 — Sample applications con default password

L'app server (Tomcat, JBoss, ecc.) viene rilasciato con app di esempio (`/manager`, `/host-manager`) e account default (`tomcat/tomcat`, `admin/admin`). Lo sviluppatore non le rimuove. L'attaccante:

1. Scansiona porte standard (es. `8080`).
2. Prova path noti: `/manager/html`.
3. Inserisce credenziali default → accesso da admin → deploy di una webshell → **RCE**.

### Scenario #2 — Directory listing abilitato

Il web server (Apache/nginx) è configurato con `Indexes` o `autoindex on`. L'attaccante richiede:

```http
GET /WEB-INF/classes/ HTTP/1.1
```

Il server elenca i file. L'attaccante scarica i `.class` Java compilati, li **decompila** (jd-gui), e legge codice sorgente, query SQL, segreti hardcoded, o trova altre falle.

### Scenario #3 — Stack trace dettagliati esposti

Configurazione del server permette messaggi di errore completi. Un input "rotto" causa:

```
Caused by: org.postgresql.util.PSQLException: ERROR: column "users.passwoord" does not exist
   at org.postgresql.core.v3.QueryExecutorImpl.receiveErrorResponse...
   at com.example.UserDao.findByEmail (UserDao.java:42)
```

L'attaccante adesso conosce: il DB è PostgreSQL, c'è un typo `passwoord`, c'è una classe `UserDao`. Material da reconnaissance per affinare un attacco — molto spesso un'**injection** (A05).

### Scenario #4 — Bucket cloud aperto a Internet

Il provider cloud ha defaulti che, se non cambi attivamente, lasciano un bucket o un blob storage **pubblico**. L'app salva backup quotidiani lì. L'attaccante scopre l'URL (Wayback, GitHub leak, scanner come `s3-scanner`), scarica i backup, ottiene tutto il database con **PII** dentro.

---

## 6. Codice / configurazioni vulnerabili vs sicure

### Esempio A — Express in produzione con stack trace

❌ **Vulnerabile** (Node/Express):

```javascript
const app = express();

app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });   // mai in prod!
});

app.listen(3000);
```

✅ **Sicuro:**

```javascript
const app = express();
app.disable('x-powered-by');                       // non rivelare framework

app.use(helmet());                                  // header di sicurezza out-of-box

app.use((err, req, res, next) => {
  logger.error({ err, req: { url: req.url, id: req.id } });   // logga server-side
  if (process.env.NODE_ENV === 'production') {
    return res.status(500).json({ error: 'Internal Server Error', requestId: req.id });
  }
  res.status(500).json({ error: err.message });   // dettagli solo in dev
});
```

### Esempio B — Header di sicurezza in nginx

❌ **Vulnerabile** (nessun header):

```nginx
server {
  listen 443 ssl;
  server_name app.example.com;
  # ... ssl_certificate ...
  location / {
    proxy_pass http://app:3000;
  }
}
```

✅ **Sicuro:**

```nginx
server {
  listen 443 ssl http2;
  server_name app.example.com;
  # ... ssl_certificate ...

  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
  add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none'" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

  server_tokens off;             # non rivelare versione nginx

  location / { proxy_pass http://app:3000; }
}
```

### Esempio C — Bucket S3 (Terraform)

❌ **Vulnerabile:**

```hcl
resource "aws_s3_bucket" "backups" {
  bucket = "company-backups"
  acl    = "public-read"      # 🚨
}
```

✅ **Sicuro:**

```hcl
resource "aws_s3_bucket" "backups" {
  bucket = "company-backups"
}

resource "aws_s3_bucket_public_access_block" "backups" {
  bucket                  = aws_s3_bucket.backups.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
```

### Esempio D — Spring Boot Actuator esposto

❌ **Vulnerabile** (`application.properties`):

```properties
management.endpoints.web.exposure.include=*
management.endpoint.env.show-values=ALWAYS
```

Espone `/actuator/env`, `/actuator/heapdump` — segreti, env vars, dump di memoria!

✅ **Sicuro:**

```properties
management.endpoints.web.exposure.include=health,info
management.endpoint.health.show-details=never
```

(E proteggi anche questi via auth se l'app è pubblica.)

---

## 7. Come prevenirlo (How to Prevent)

1. **Processo di installazione ripetibile** e versionato (Infrastructure-as-Code: Terraform, Ansible, Pulumi). Installare un nuovo ambiente deve essere veloce, deterministico e *appropriately locked down* — non manuale.
2. **Piattaforma minimale.** Niente componenti, feature, esempi, frameworks di test in produzione.
3. **Review delle configurazioni** come parte del processo di patch management. La configurazione cambia, va riverificata.
4. **Architettura segmentata.** Separazione di rete (VPC, subnet, security group) e applicativa (microservizi, container con namespace e capability minime).
5. **Direttive di sicurezza al client** = gli header sopra (HSTS, CSP, ecc.).
6. **Verifica automatica.** Tool che scansionano la config: **Trivy**, **Checkov**, **kube-bench**, **CIS Benchmark**, **Mozilla Observatory** (per header HTTP), **ScoutSuite** o **Prowler** per cloud.
7. **Centralizzazione errori.** Un handler centrale che intercetta tutto e produce messaggi sicuri. Vedi anche A10.
8. **Identity federation e credenziali short-lived.** Non hardcodare segreti: usa **OIDC** + role-based, **AWS IAM Roles**, **Vault**, secrets manager. Le credenziali devono essere a vita breve e ruotate.

---

## 8. CWE rilevanti

| CWE | Nome |
|-----|------|
| **CWE-16** | Configuration |
| **CWE-260** | Password in Configuration File |
| **CWE-489** | Active Debug Code |
| **CWE-611** | Improper Restriction of XML External Entity Reference (**XXE**) |
| **CWE-614** | Sensitive Cookie in HTTPS Session Without 'Secure' Attribute |
| **CWE-1004** | Sensitive Cookie Without 'HttpOnly' Flag |
| **CWE-13** | ASP.NET Misconfiguration: Password in Configuration File |
| **CWE-5** | J2EE Misconfiguration: Data Transmission Without Encryption |

---

## 9. Lab pratico

### Lab consigliati

1. **PortSwigger Academy — Information Disclosure**: <https://portswigger.net/web-security/information-disclosure> (debug pages, stack trace, error message disclosure).
2. **OWASP Juice Shop** — sfide *"Misconfiguration"* e *"Disclosure"*.
3. **Mozilla Observatory** — analizza il tuo (o un) sito vivo: <https://observatory.mozilla.org/>. Ti dà un voto da F a A+ con i fix concreti per ogni header.
4. **TryHackMe — "OWASP Top 10" room** (gratuita) include task su Security Misconfiguration.

### 🧪 Esercizio guidato — Hardening di un'app Express

1. Crea un'app `express` minimale con un endpoint `GET /` e un middleware di errore.
2. Lanciala su `localhost:3000` e fai una richiesta. Apri dev-tools → Network → guarda gli **header di risposta**.
3. Conta quanti header di sicurezza ci sono. (Risposta tipica: zero, e c'è `X-Powered-By: Express` 🤦)
4. Aggiungi `helmet()` e `app.disable('x-powered-by')`.
5. Rifai la richiesta e conta di nuovo. Dovresti vedere ~10 header in più.
6. Apri Mozilla Observatory e guarda quale voto otterresti.

✅ **Hai completato** se: ottieni almeno un B+ su Mozilla Observatory e non c'è più `X-Powered-By`.

---

## 10. Quiz di autovalutazione

1. Perché A02 ha il **massimo incidence rate** della Top 10?
2. Cosa ti permette di prevenire l'header `Strict-Transport-Security`?
3. Differenza tra `X-Content-Type-Options: nosniff` e `Content-Security-Policy`?
4. In Node/Express, qual è il pacchetto npm più usato per impostare gli header di sicurezza?
5. `management.endpoints.web.exposure.include=*` in Spring Boot perché è pericoloso?
6. Bucket S3: la differenza tra **policy** e **ACL** ti permette di… (cosa)?
7. Perché lasciare gli **stack trace** in risposta è un problema, anche se "tanto solo l'utente li vede"?
8. Che differenza c'è tra **least privilege** applicato a un IAM role e a un cookie di sessione?

<details>
<summary>📖 Soluzioni</summary>

1. Perché ogni layer dello stack moderno (cloud, container, framework, app, CDN, mesh) ha decine di setting; le opzioni di default raramente sono "sicuro"; e la maggior parte degli sviluppatori non rivede *tutti* i setting di *tutti* i layer.
2. **HSTS** dice al browser "questo dominio si raggiunge solo via HTTPS" e impedisce attacchi di **downgrade** (man-in-the-middle che forza HTTP). È strettamente legato ad A04.
3. `nosniff` impedisce al browser di "indovinare" il MIME type (utile contro alcuni XSS via upload). **CSP** è una politica molto più ricca che dichiara da dove possono caricarsi script, immagini, frame, ecc.: è la difesa principe contro XSS (A05).
4. **`helmet`** (npm `helmet`). Spring Boot ha `Spring Security` headers; in Python/Django c'è il middleware `SecurityMiddleware`.
5. Espone tutti gli endpoint Actuator: `/env`, `/heapdump`, `/loggers`, `/beans`. Da `/env` un attaccante legge segreti, da `/heapdump` scarica un dump di memoria. Va limitato a `health,info` e protetto.
6. Le **ACL** sono il vecchio modello (oggi sconsigliato). Le **bucket policy + Public Access Block** sono il modello moderno: blocchi a livello di account/bucket l'accesso pubblico anche se qualcuno si "dimentica". Il combinato evita errori umani.
7. Perché "solo l'utente" è qualunque cosa: utenti malintenzionati, scraper, bot. Lo stack trace rivela framework, versioni, path, struttura del codice, talvolta query e segreti. È **reconnaissance** che alimenta attacchi successivi.
8. **IAM** = i permessi che un servizio/persona ha sull'infrastruttura (es. "questo container può solo leggere quel bucket"). **Cookie di sessione**: i flag (`Secure`, `HttpOnly`, `SameSite`) limitano *come* il cookie viene esposto. In entrambi vale "minimo necessario, niente di più".

</details>

---

## 11. Cheat sheet — A02 in 60 secondi

- 📈 **#2 della Top 10** (era #5 nel 2021), **massima incidenza** (27.70%).
- 🧱 **Hardening = processo ripetibile e automatizzato**, non un'attività manuale "una tantum".
- 🚪 Rimuovi tutto ciò che **non serve in prod**: account default, sample app, debug, framework di test, doc.
- 🛡️ **Header obbligatori:** HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- ☁️ **Cloud:** Public Access Block sempre; IAM least-privilege; secrets in vault, mai in env file in repo.
- 🩺 **Verifica con tool:** Mozilla Observatory, Trivy, Checkov, kube-bench, ScoutSuite/Prowler.
- 🚫 **Niente stack trace** in risposta in produzione.
- 🍪 Ogni cookie sensibile: `Secure`, `HttpOnly`, `SameSite`.

---

## 12. Risorse e approfondimenti

- 🌐 [Pagina OWASP A02:2025](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
- 📘 [OWASP Cheat Sheet — HTTP Security Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- 📘 [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- 🩺 [Mozilla Observatory](https://observatory.mozilla.org/) — voto immediato dei tuoi header
- 🩺 [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/) — config TLS ready-to-paste
- 🛠️ [helmet (npm)](https://helmetjs.github.io/) — header sicurezza per Express
- 🛠️ [Trivy](https://trivy.dev/) — scanner config + container
- 🛠️ [Checkov](https://www.checkov.io/) — scanner IaC (Terraform, CloudFormation, K8s)
- 📘 [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) — hardening guides per OS/cloud/k8s
- 📖 [content-security-policy.com](https://content-security-policy.com/) — guida pratica CSP

---

⬅ Modulo precedente: [01_broken_access_control.md](01_broken_access_control.md)
➡ Prossimo: [03_software_supply_chain_failures.md](03_software_supply_chain_failures.md)

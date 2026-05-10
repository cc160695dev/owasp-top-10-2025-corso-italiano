# A03:2025 — Compromissione della catena di fornitura software (Software Supply Chain Failures)

> ✨ **Categoria espansa nel 2025.** Era "Vulnerable & Outdated Components" (A06 nel 2021, A09 nel 2017). Ora copre **tutto** il ciclo di build/distribuzione/aggiornamento: package npm/PyPI, CI/CD, IDE, vendor di terze parti, aggiornamenti automatici. Esempi 2025: il worm npm **Shai-Hulud** e l'attacco **Bybit** da $1.5B.

---

## 1. Obiettivi (Learning Objectives)

Alla fine di questo modulo saprai:

- Spiegare cos'è la **catena di fornitura software** (supply chain) e perché è un bersaglio.
- Conoscere casi reali: **SolarWinds (2019)**, **Log4Shell (2021)**, **Bybit (2025)**, **Shai-Hulud (2025)**.
- Generare e interpretare un **SBOM** (Software Bill of Materials).
- Configurare scanner di dipendenze (**OWASP Dependency-Check**, **Dependency-Track**, `npm audit`, `pip-audit`, **Trivy**).
- Hardenare una pipeline **CI/CD** (separation of duties, signing, build immutabili, rollouts staged).

---

## 2. Prerequisiti

- Sapere cos'è un **package manager** (npm, pip, Maven, Gradle, NuGet, Cargo).
- Sapere cos'è una **pipeline CI/CD** (GitHub Actions / GitLab CI / Jenkins).
- Concetto di **dipendenze transitive** (la libreria che usi tira dentro altre librerie a sua volta).

---

## 3. Background OWASP

| Metrica | Valore |
|---------|--------|
| Posizione 2025 | **#3** ✨ (espansa, era #6 nel 2021) |
| CWE mappati | 6 |
| Max incidence rate | 9.56% |
| Avg incidence rate | 5.72% |
| Total occurrences | 215.248 |
| Total CVE | 11 (basso, ma exploit weight 8.17 — molto alto) |

> 📌 **Cosa è cambiato:** dal 2013 (A9 — *"Using Components with Known Vulnerabilities"*) la categoria si è espansa progressivamente. Nel 2025 abbraccia **l'intero pipeline**: vendor compromessi, malware in package legittimi, CI/CD attaccati, IDE e workstation degli sviluppatori come **target diretti**.

---

## 4. Descrizione (Description)

> *"Software supply chain failures are breakdowns or compromises in the process of building, distributing, or updating software."* — OWASP

Sei probabilmente vulnerabile se:

1. **Non tracci le versioni** di tutti i componenti (incluse le dipendenze transitive, sia client-side che server-side).
2. Hai **componenti vulnerabili, unsupported, o vecchi**: OS, web/app server, DBMS, runtime, librerie.
3. **Non scansioni regolarmente** per vulnerabilità e non sei iscritto ai bollettini di sicurezza dei componenti.
4. **Non c'è change management** per la supply chain: chi cambia le IDE? Chi modifica le immagini base dei container? Chi ha accesso ai repository artefatti?
5. Non hai **hardenato** ogni parte della supply chain (focus su access control e least privilege).
6. **Manca separation of duty**: una persona può scrivere codice e portarlo fino in prod senza un secondo occhio umano.
7. Usi **componenti da fonti non trusted**.
8. Aggiorni con **cadenze fisse** (mensile/quarterly) invece che **risk-based**, lasciando finestre di esposizione enormi.
9. **Non testi** la compatibilità di patch e upgrade.
10. **Non securi le configurazioni** di nessuna parte del sistema.
11. Il tuo **CI/CD ha sicurezza più debole** dei sistemi che costruisce e deploya — spesso vero in pipeline complesse.

### Tre famiglie di attacco da capire

| Famiglia | Esempio | Dove avviene |
|----------|---------|--------------|
| **Vendor compromise** | SolarWinds (Orion) | il vendor "buono" viene bucato; il suo update è velenoso |
| **Malicious package** | Shai-Hulud (npm 2025), event-stream (2018), `colors`/`faker` sabotage (2022) | malware iniettato in package legittimi o pubblicati con typo-squatting |
| **Pipeline / dev tooling compromise** | Token CI rubati, IDE plugin malevoli | l'attacco non è sul codice, è su chi lo costruisce |

---

## 5. Esempi di attacco (Example Attack Scenarios)

### Scenario #1 — SolarWinds (2019)

Attaccanti compromettono la build chain di **SolarWinds Orion** e iniettano una backdoor (SUNBURST). Quando ~18.000 organizzazioni installano l'aggiornamento "ufficiale" firmato dal vendor, sono compromesse silenziosamente. Vittime: agenzie federali USA, Microsoft, FireEye.

> 🔑 **Lezione:** la firma del vendor *autentica la fonte*, **non garantisce che la fonte non sia compromessa**.

### Scenario #2 — Bybit / wallet supply chain (2025)

Una libreria di wallet fidata viene compromessa per eseguire codice malevolo **solo a una condizione specifica** (target wallet in uso). Risultato: $1.5 miliardi rubati a Bybit. La compromissione è **dormiente e mirata**, quindi sfugge ai test di sicurezza standard ("ho usato questa libreria mille volte e non è mai successo niente").

### Scenario #3 — Shai-Hulud, primo worm self-propagating su npm (2025)

Sequenza dell'attacco:

1. Versioni malevole di pacchetti popolari vengono pubblicate.
2. Uno **script `postinstall`** del package, eseguito automaticamente da `npm install`, **harvest** segreti dalla macchina della vittima e li **exfiltra** in repo GitHub pubbliche.
3. Lo script trova **token npm** della vittima nell'ambiente di sviluppo.
4. Usa quei token per **pubblicare versioni malevole** di altri package a cui la vittima ha accesso → **propagazione autonoma**.

In pochi giorni il worm arriva a >500 versioni di package prima che npm lo blocchi.

> 🔑 **Lezione:** **gli sviluppatori sono il target**. La macchina dello sviluppatore (token, chiavi SSH, browser session) è oggi quanto un server di produzione del 2010.

### Scenario #4 — Vulnerable Components

Le librerie girano con **gli stessi privilegi dell'app**. Esempi:

- **CVE-2017-5638** — Struts 2 RCE → causa del breach Equifax (147M record).
- **CVE-2021-44228** — *Log4Shell* — RCE 0-day in Apache Log4j → ondata globale di ransomware e cryptomining. Patch banale (aggiornare Log4j), ma molte org la avevano *transitiva* in dipendenze e nemmeno lo sapevano.

---

## 6. Pratiche / configurazioni vulnerabili vs sicure

### Esempio A — Pinning delle dipendenze (Node)

❌ **Vulnerabile** (`package.json`):

```json
"dependencies": {
  "express": "^4.0.0",
  "lodash": "*"
}
```

`^` permette upgrade minor automatici, `*` qualsiasi versione. Una nuova versione malevola viene installata silenziosamente.

✅ **Sicuro:**

```json
"dependencies": {
  "express": "4.21.0",
  "lodash": "4.17.21"
}
```

E **commetti il `package-lock.json`** in git. In CI usa `npm ci` (deterministic install), non `npm install`.

### Esempio B — `postinstall` script ostili

❌ Quando installi un package npm sconosciuto, il suo `postinstall` può eseguire codice arbitrario sul tuo PC.

✅ **Mitigazione:**

```bash
# globalmente o in CI
npm config set ignore-scripts true
```

E poi abilita gli script solo per dipendenze fidate selezionate.

### Esempio C — GitHub Actions con permessi minimi

❌ **Vulnerabile** (`.github/workflows/build.yml`):

```yaml
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main         # tag mobile
      - run: ./build.sh
```

Problemi: `actions/checkout@main` (tag mobile, non pinned), nessuna restrizione di permission, qualsiasi PR può eseguire codice arbitrario con il `GITHUB_TOKEN` di scrittura.

✅ **Sicuro:**

```yaml
on: [pull_request]
permissions:
  contents: read           # least privilege esplicito
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11   # pin a SHA
        with:
          persist-credentials: false
      - run: ./build.sh
```

### Esempio D — Generare un SBOM

```bash
# CycloneDX per progetto Node
npx @cyclonedx/cyclonedx-npm --output-file sbom.json

# Per Python (dal lockfile)
pip install cyclonedx-bom
cyclonedx-py requirements -r requirements.txt -o sbom.json

# Per container (con syft)
syft my-image:latest -o cyclonedx-json > sbom.json
```

L'SBOM va **conservato** insieme all'artefatto e **aggiornato a ogni build**. Usalo per cercare CVE retrospettivamente quando appare un nuovo exploit.

---

## 7. Come prevenirlo (How to Prevent)

### 7.1. Patch / dependency management

- **Genera e gestisci centralmente l'SBOM** dell'intero software.
- **Traccia le dipendenze transitive**, non solo quelle dirette.
- **Riduci la superficie**: rimuovi dipendenze e feature non usate.
- **Inventario continuo** delle versioni client e server. Tool: **OWASP Dependency-Track**, **OWASP Dependency-Check**, **retire.js**, **Trivy**, **Snyk**, `npm audit`, `pip-audit`, `cargo audit`.
- **Monitora CVE/NVD/OSV** per i componenti che usi. Subscribe agli alert.
- **Solo fonti ufficiali** (npm registry ufficiale, PyPI, Maven Central). Preferisci pacchetti **firmati**. Mirror interni con allow-list quando possibile.
- **Versioni deliberate**: scegli quando aggiornare, non aggiornare in modo automatico/floating in produzione.
- **Componenti unmaintained** → migra o virtual patch (WAF/IPS regola).
- **Tooling dev** (CI/CD, IDE, plugin) **regolarmente aggiornati**.
- **Staged / canary rollouts** invece di deploy simultaneo a tutti i sistemi: limita il blast radius se un vendor è compromesso.

### 7.2. Change management

Tracciare cambi a:

- CI/CD (build tools, pipelines)
- Code repository
- Sandbox
- IDE degli sviluppatori
- SBOM tooling
- Logging
- Integrazioni SaaS (la tua chain include OAuth con vendor terzi!)
- Artifact / container registry

### 7.3. Hardening dei sistemi

Abilita **MFA**, blocca **IAM**, su:

- **Code repo:** niente segreti committati, branch protection (PR obbligatorie, recensione, status check), backup off-platform.
- **Workstation dev:** patching regolare, MFA, monitoring (EDR), full-disk encryption, niente accessi admin permanenti.
- **Build server / CI/CD:** separation of duties (chi committa ≠ chi rilascia), access control granulare, **build firmati** (Sigstore/cosign), **secrets scoped** (per environment, ephemeral), **tamper-evident logs**.
- **Artefatti:** integrità via **provenance** (SLSA), firma e timestamp. Promuovi artefatti tra ambienti invece di rebuildare. Build **immutabili**.
- **IaC:** versionato come codice, PR e review obbligatori.

> 🔑 **Concetto chiave — SLSA (Supply-chain Levels for Software Artifacts):** framework di Google adottato dall'industria che definisce 4 livelli di garanzia sull'integrità degli artefatti (L1 → L4). Vedi <https://slsa.dev/>.

---

## 8. CWE rilevanti

| CWE | Nome |
|-----|------|
| **CWE-1395** | Dependency on Vulnerable Third-Party Component |
| **CWE-1104** | Use of Unmaintained Third Party Components |
| **CWE-1357** | Reliance on Insufficiently Trustworthy Component |
| **CWE-1329** | Reliance on Component That is Not Updateable |
| **CWE-1035** | Using Components with Known Vulnerabilities (Top 10 storico) |
| **CWE-447** | Use of Obsolete Function |

---

## 9. Lab pratico

### Lab consigliati

1. **OWASP Dependency-Check / Dependency-Track demo**:
   - <https://dependencytrack.org/>
   - Importa l'SBOM di un tuo progetto reale e vedi quanti CVE escono.
2. **TryHackMe — "Solar, exploiting Log4j"** (gratuito):
   - <https://tryhackme.com/r/room/solar>
   - Sfrutta Log4Shell in un lab controllato.
3. **GitHub Security Lab — CodeQL workshops**: <https://securitylab.github.com/>

### 🧪 Esercizio guidato — Audit di un progetto Node esistente

1. Clona un tuo progetto (o `git clone https://github.com/expressjs/express`).
2. Lancia: `npm audit --json > audit.json`.
3. Apri `audit.json`: quanti **high** e **critical** ci sono?
4. Genera l'SBOM:
   ```bash
   npx @cyclonedx/cyclonedx-npm --output-file sbom.json
   ```
5. Apri **Dependency-Track** (Docker quickstart) e importa `sbom.json`.
6. Esamina: quante dipendenze transitive non avevi mai notato?
7. Scegli una vulnerabilità high → identifica il pacchetto e il path di dipendenza (`npm ls <pkg>`) → trova la versione patched → aggiorna.
8. Lancia di nuovo `npm audit`: il count è sceso?

✅ **Hai completato** se: hai capito la catena `package diretto → transitive → CVE` e ridotto il count di **almeno una** vulnerabilità high.

---

## 10. Quiz di autovalutazione

1. Differenza tra una **dipendenza diretta** e una **transitiva**? Perché conta in security?
2. Cos'è un **SBOM** e in che formato standard si scambia?
3. Perché un *postinstall script* npm è considerato pericoloso?
4. **SolarWinds** e **Shai-Hulud** sono entrambi attacchi alla supply chain ma di natura diversa: come?
5. Quale comando in npm garantisce un'installazione **deterministica** in CI?
6. Cosa significa **"least privilege"** applicato a una pipeline GitHub Actions?
7. Perché i **rollout staged/canary** sono una difesa contro la supply chain (oltre che una buona pratica di affidabilità)?
8. Cosa è **SLSA** e a cosa serve?
9. Hai dipendenze pinnate a versione esatta. È **sufficiente**? Perché sì o no?

<details>
<summary>📖 Soluzioni</summary>

1. **Diretta**: la dichiari tu in `package.json`/`requirements.txt`. **Transitiva**: viene tirata dentro perché una tua diretta la usa. Conta perché la maggior parte del codice "tuo" in produzione è in realtà **transitivo**, fuori dal tuo controllo diretto.
2. *Software Bill of Materials* — la "lista degli ingredienti" del software. Standard: **CycloneDX** (OWASP) e **SPDX** (Linux Foundation). Permette inventario, audit retrospettivo (es. "quali nostre app contengono Log4j 2.14?") e compliance (es. SBOM richiesti per fornire al governo USA, EU NIS2).
3. Perché viene eseguito **automaticamente** su `npm install`, con i privilegi dell'utente che installa (spesso una macchina di sviluppo con token, chiavi SSH, ambienti di lavoro). Esattamente il vettore di Shai-Hulud.
4. **SolarWinds** = vendor *fidato* compromesso (l'update firmato è velenoso). **Shai-Hulud** = malware in pacchetti pubblici della community, con propagazione **autonoma** (worm) tramite token rubati. La prima è "alta sofisticazione, target verticale"; il secondo è "rapido, orizzontale, su massa di sviluppatori".
5. **`npm ci`** (clean install) — installa esattamente quanto sta in `package-lock.json`, senza modificare il lock; fallisce se il lock è incoerente. È deterministico e più veloce.
6. Significa che il `permissions:` del workflow / job dichiari esplicitamente solo i permessi che servono (es. `contents: read`), invece di usare il default permissivo. Limita cosa un eventuale codice malevolo eseguito nel workflow può fare (es. non può scrivere sui contents, non può pubblicare release).
7. Perché se il vendor / la dipendenza è compromessa, il rollout incrementale **limita il blast radius**: te ne accorgi sul 5% prima del 100%. Combinato con monitoring/alerting (A09), è una difesa di tempo.
8. *Supply-chain Levels for Software Artifacts* — framework Google/OpenSSF. Definisce 4 livelli di garanzia di integrità su come un artefatto è stato costruito (provenance, build hermetic, source attestato). Permette di **dichiarare** e **verificare** il livello di trust.
9. **No.** Il pinning protegge da upgrade non desiderati ma **non** da una versione *retroattivamente* segnata come malevola (la versione esatta che hai potrebbe diventare cattiva). Servono anche: scansione continua, monitoring CVE, firma/SBOM, mirror controllati.

</details>

---

## 11. Cheat sheet — A03 in 60 secondi

- 🔗 La **supply chain** è tutto: package, CI/CD, IDE, registries, vendor SaaS.
- 📦 **SBOM sempre**, formato **CycloneDX** o **SPDX**, archiviato con l'artefatto.
- 🔍 **Scanner continui**: Dependency-Track, Trivy, Snyk, `npm audit`, `pip-audit`.
- 📌 **Pin** + lockfile committato + `npm ci` / `pip install --require-hashes` in CI.
- ✋ `npm config set ignore-scripts true` in CI; abilita solo per pacchetti fidati.
- 🔐 **CI/CD hardened**: permessi minimi, secrets scoped+ephemeral, build firmati (cosign/Sigstore), build immutabili, **promote** invece di rebuild.
- 🚦 **Staged rollouts** per limitare blast radius.
- 👥 **MFA + branch protection + 2-person review** per qualunque cambio in path critico.
- 🎯 Tre famiglie: **vendor compromise**, **malicious package**, **pipeline/dev compromise**.
- 📚 Casi: SolarWinds (2019), Log4Shell (2021), Bybit ($1.5B, 2025), Shai-Hulud (npm worm, 2025).

---

## 12. Risorse e approfondimenti

- 🌐 [Pagina OWASP A03:2025](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)
- 📘 [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- 📘 [OWASP Dependency-Track](https://dependencytrack.org/)
- 📘 [OWASP CycloneDX](https://cyclonedx.org/)
- 📘 [OWASP Software Component Verification Standard (SCVS)](https://owasp.org/www-project-software-component-verification-standard/)
- 🛠️ [Sigstore / cosign](https://www.sigstore.dev/) — firma artefatti
- 🛠️ [SLSA framework](https://slsa.dev/) — livelli di garanzia
- 🛠️ [Trivy](https://trivy.dev/) — scanner CVE per filesystem/container/IaC
- 🛠️ [Snyk Open Source](https://snyk.io/) — alternativa commerciale con free tier
- 🛠️ [GitHub Dependabot](https://docs.github.com/en/code-security/dependabot)
- 📖 [SolarWinds breach — Microsoft postmortem](https://www.microsoft.com/en-us/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/)
- 📖 [Log4Shell — CISA advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a)
- 📖 [Shai-Hulud npm worm writeup (2025)](https://socket.dev/blog) — segui blog Socket.dev / Snyk

---

⬅ Modulo precedente: [02_security_misconfiguration.md](02_security_misconfiguration.md)
➡ Prossimo: [04_cryptographic_failures.md](04_cryptographic_failures.md)

# Lab: Configure PAM to Limit root Access (`pam_securetty.so`)

**Series:** linux-ops-mastery — RHCSA TCP Wrappers & PAM
**Subjects covered:** **`pam_securetty.so`**, **`/etc/securetty`**, root **console** login policy, **virtual terminals** (`tty1`–`tty6`), verifying `login` PAM stack, **rollback** of `securetty`, relationship to **SSH** (`PermitRootLogin` separate)
**Career arcs covered:** RHCSA (console hardening), RHCE (controlled `lineinfile`), SRE (break-glass planning), DevOps (CIS benchmarks), AI (policy simulation)
**Prerequisite:** Lab 73 — Read PAM Module Documentation
**Time Estimate:** 30 to 45 minutes
**Difficulty arc:** Task 1 backups · 2–3 inspect pam stack · 4 reduce securetty to tty6 only · 5 verification plan · 6 capstone + restore securetty + pam backups

---

## Objective

Implement a strict **root console allowlist**: only **`tty6`** may be used for **root password-based login** via the **`login`** program, enforced by **`pam_securetty.so`** reading **`/etc/securetty`**. This is a classic **defense-in-depth** exercise for bare-metal and VM consoles — *not* a replacement for SSH hardening.

You will backup **`/etc/securetty`** and **`/etc/pam.d/login`** (or its authselect-resolved target), apply the minimal tty list, and describe how you would **verify** on a physical console (switching VTs with **Ctrl+Alt+F6** on many systems). You will restore everything in Task 6 so the VM returns to stock behavior.

> **Lab safety note:** Misconfiguring **`pam_securetty`** or emptying **`/etc/securetty`** incorrectly can block **root on tty1** during emergencies. Perform this lab on a **VM with console access**, not a remote-only production server. Keep your **non-root sudo admin** working.

---

## Concept: `/etc/securetty` Is the Allowlist File, `pam_securetty` Enforces It

For local **`login`**, the **`auth`** stack typically includes **`pam_securetty.so`**. If the tty device name (e.g., `tty6`) is absent from **`/etc/securetty`**, **root** authentication fails on that console — while non-root flows may differ based on other modules.

```
Ctrl+Alt+F6 → /dev/tty6 → login prompts for root
                 │
                 └─ pam_securetty: is 'tty6' in /etc/securetty?
                        ├── YES → continue PAM stack
                        └── NO  → root password path fails
```

> **Why this matters:** Examiners want you to connect **module name**, **config file**, and **observed behavior** — not just "I edited a file."

---

## 📜 Why Limiting root to One VT Exists — The Story

Before pervasive remote administration, **root logged in on the physical console** constantly. **`pam_securetty`** gave sites a crude but effective knob: **only these keyboards may ever see a successful root password prompt**. Hardening guides often shrank the list to a **single known VT** in high-security rooms: "root uses station six."

SSH changed habits: most root access moved to network paths governed by **`PermitRootLogin`**, keys, and MFA. Still, **single-user mode**, **idrac serial**, and **KVM** exist — **`securetty`** remains the answer to *"which local TTY names are even eligible?"*

> **The point of the story:** You are practicing **explicit trust** on local consoles — the same philosophy as **allowlisting jump hosts**, just at the TTY layer.

---

## 👪 The securetty Family — Who Lives There

| Artifact | Role |
|---|---|
| `/etc/securetty` | Allowlist of tty base names |
| `/etc/pam.d/login` | Invokes `pam_securetty.so` |
| `/dev/ttyN` | Device nodes for virtual consoles |
| `man pam_securetty` | Module options (`noconsole`, etc.) |

### Not the same as

| Mechanism | Layer |
|---|---|
| `PermitRootLogin` | SSH daemon |
| `sudo` | privilege elevation |
| `/etc/nologin` | blocks non-root interactive logins (Lab 76) |

> **The point of the family tree:** **Layer isolation** prevents "I fixed SSH" from accidentally answering a **console** question.

---

## 🔬 The Anatomy of `/etc/securetty` After Hardening — In One Diagram

```
/etc/securetty (lab goal)
  tty6
  (end)

Meaning:
  Only tty6 name is trusted for pam_securetty checks
```

> **Reading rule:** Names are typically **`tty6`**, not **`/dev/tty6`** — match what `tty` prints.

---

## 📚 pam_securetty / securetty Reference Table

| Task | Command | Notes |
|---|---|---|
| Show tty name | `tty` | Run on each console |
| Backup | `cp -a /etc/securetty /root/securetty.bak` | Mandatory |
| Apply allowlist | `printf '%s\n' 'tty6' > /etc/securetty` | Lab minimalism |
| Confirm pam line | `grep pam_securetty /etc/pam.d/login` | Stack proof |
| Restore | `cp -a /root/securetty.bak /etc/securetty` | Rollback |

> **Rule one of console hardening:** **Verify from tty6**, not only from SSH observations.

---

## 🎯 Career Pathway Sidebar

| Level | Why this lab matters |
|---|---|
| **RHCSA candidate** | Tie **`pam_securetty`** ↔ **`/etc/securetty`** cold |
| **RHCE candidate** | Guard playbooks: only apply with `serial: 1` + console |
| **SRE / Platform** | Document which VT is the **approved root console** |
| **DevOps** | CIS controls reference `/etc/securetty` |

---

## 🔧 The 6 Tasks

---

### Task 1 — Back up securetty and login stack

**Purpose:** One-command rollback files.

```bash
sudo -i
TS=$(date +%F-%H%M%S)
cp -a /etc/securetty /root/securetty.$TS
cp -a /etc/pam.d/login /root/login.$TS

readlink -f /etc/pam.d/login || true
```

**Human-Readable Breakdown:** Timestamped copies in `/root`.

**Reading it left to right:** copy securetty → copy login → optional symlink resolve.

**The story:** **Two-file backup** because incidents sometimes touch both.

**Expected output:**

```text
/etc/pam.d/login
```

**Switches**

| Token | Meaning |
|---|---|
| `cp -a` | Preserve metadata |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| login is symlink | Backup resolved file too: `cp -a $(readlink -f /etc/pam.d/login) /root/login.real.$TS` |

---

### Task 2 — Confirm `pam_securetty` is in the `login` stack

**Purpose:** Prove enforcement path exists before editing lists.

```bash
grep -n 'pam_securetty' /etc/pam.d/login || grep -n 'pam_securetty' $(readlink -f /etc/pam.d/login) 2>/dev/null
```

**Human-Readable Breakdown:** Search primary and resolved targets.

**Reading it left to right:** grep pam line.

**The story:** If module missing, editing **`securetty`** will not change behavior.

**Expected output:**

```text
8:auth ... pam_securetty.so
```

**Switches**

| Token | Meaning |
|---|---|
| `grep -n` | Show line numbers |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| No pam_securetty | Do not continue hardening — investigate image |

---

### Task 3 — Record current tty list length

**Purpose:** Before/after metric.

```bash
wc -l /etc/securetty
head -n 5 /etc/securetty
```

**Human-Readable Breakdown:** Count lines; preview top entries.

**Reading it left to right:** `wc` → `head`.

**The story:** Quantify how aggressive your hardening is.

**Expected output:**

```text
31 /etc/securetty
tty1
tty2
...
```

**Switches**

| Token | Meaning |
|---|---|
| `wc -l` | Line count |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Unexpected contents | Vendor defaults differ — still safe if you have backups |

---

### Task 4 — Restrict `/etc/securetty` to **tty6** only

**Purpose:** Implement the lab policy.

```bash
printf '%s\n' 'tty6' > /etc/securetty
chmod 644 /etc/securetty
cat /etc/securetty
```

**Human-Readable Breakdown:** Replace file with single tty entry.

**Reading it left to right:** atomic overwrite → perms → cat.

**The story:** **Minimal allowlist** is the clearest exam answer.

**Expected output:**

```text
tty6
```

**Switches**

| Token | Meaning |
|---|---|
| `printf '%s\n'` | Writes single line with newline |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Need serial console too | Also add `ttyS0` per environment — not part of this narrow lab |

---

### Task 5 — Document verification procedure (console-centric)

**Purpose:** RHCSA answers include **how you tested**.

```bash
cat > /root/securetty-verify.txt <<'EOF'
Verification plan:
1. Open VM console (not SSH-only proof).
2. Switch to virtual console 6 (often Ctrl+Alt+F6 on physical; hypervisor key for VMs).
3. Attempt: login: root  → expect PAM stack to allow IF pam_securetty permits tty6.
4. Switch to tty1 and repeat → expect root password login to FAIL under this lab policy.
5. Confirm non-root test user still behaves per other PAM modules.
EOF
cat /root/securetty-verify.txt
```

**Human-Readable Breakdown:** Written test plan — execute manually in class.

**Reading it left to right:** heredoc → cat.

**The story:** **SSH success does not prove console policy** — write that in interviews.

**Expected output:**

```text
Verification plan:
1. Open VM console...
```

**Switches**

| Token | Meaning |
|---|---|
| `/root/securetty-verify.txt` | Evidence artifact |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Cannot send Ctrl+Alt+F6 | Use hypervisor "send key" menu |

---

### Task 6 — Capstone + restore `/etc/securetty` and pam backups

**Purpose:** Return to vendor defaults from backup.

```bash
# Replace TIMESTAMP with the value you captured in Task 1 (example: 2026-05-26-103045)
cp -a /root/securetty.TIMESTAMP /etc/securetty
cp -a /root/login.TIMESTAMP /etc/pam.d/login

wc -l /etc/securetty | sed 's/^/restored lines: /'
```

**Cleanup**

```bash
rm -f /root/securetty.* /root/login.* /root/securetty-verify.txt 2>/dev/null
exit
```

**Human-Readable Breakdown:** Restore both files from Task 1 timestamped copies — use `ls -1 /root/securetty.*` to copy/paste the exact suffix.

**Reading it left to right:** `cp -a` restore → line count check.

**The story:** **Capstone includes proof** you undid the hardening.

**Expected output:**

```text
restored lines: 31 /etc/securetty
```

**Switches**

| Token | Meaning |
|---|---|
| `cp -a` | Restore metadata |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Forgot TS value | `ls -1 /root/securetty.*` and copy/paste |

---

## 🔍 root Console Limiting Decision Guide

```
Want to limit root local logins?
  │
  ├── Primary surface is SSH?
  │       └── Tune /etc/ssh/sshd_config PermitRootLogin + keys
  │
  ├── Primary surface is console login?
  │       └── ✅ /etc/securetty + pam_securetty on login stack
  │
  ├── Need serial console root?
  │       └── Add ttyS0/ttyUSB0 as policy demands
  │
  └── authselect-managed login file?
          └── Changes may require custom profile — consult admin guide
```

---

## ✅ Lab Checklist (6 Tasks)

- [ ] 01 Backup `/etc/securetty` and `/etc/pam.d/login`
- [ ] 02 Confirm `pam_securetty.so` present in login stack
- [ ] 03 Measure baseline securetty lines
- [ ] 04 Replace `/etc/securetty` with only `tty6`
- [ ] 05 Write console verification plan
- [ ] 06 Restore securetty + login from backups; delete artifacts

---

## ⚠️ Common Pitfalls

| Mistake | Symptom | Fix |
|---|---|---|
| Testing only via SSH | False confidence | Use VM console |
| Wrong tty name | Policy ineffective | Use `tty` output |
| Removing pam line "to fix" | Different security hole | Never ad-hoc remove PAM |
| Forgetting serial consoles | ILO/DRAC lockout | Add `ttyS0` if needed |
| Not restoring securetty | Next lab weird | Task 6 restore |

---

## 🎯 Career & Interview Strategy

**RHCSA candidate**
- Answer: **`pam_securetty` reads `/etc/securetty` for root console logins.**

**RHCE candidate**
- Add `notify: authselect apply-changes` if your org uses profiles.

**SRE / Platform interview**
- Emphasize **break-glass**: always know non-root sudo path + console.

**DevOps**
- Store baseline `/etc/securetty` checksum in image tests.

**AI / MLOps**
- Never recommend empty `securetty` without explicit emergency design.

---

## 🔗 Related Labs

| Lab | Connection |
|---|---|
| Lab 73 — pam_securetty documentation | Man page foundation |
| Lab 76 — /etc/nologin | Different gate (non-root) |
| Lab 77 — pam_listfile | User list deny |

---

## 👤 Author

**Kelvin R. Tobias**
[kelvinintech.com](https://kelvinintech.com) · [GitHub](https://github.com/kelvintechnical) · [LinkedIn](https://www.linkedin.com/in/kelvin-r-tobias-211949219)

# Lab: Configure PAM to Limit root Access — `pam_securetty.so`, `/etc/securetty`, `/etc/pam.d/login`

- **Series:** linux-ops-mastery — RHCSA TCP Wrappers & PAM
- **Subjects covered:** What `pam_securetty.so` actually checks; how `/etc/pam.d/login` invokes it; why interactive root logins must be restricted to a known set of terminals; the RHEL 9 reality that `/etc/securetty` is no longer shipped by default and the module falls back to its built-in list (`tty1..tty11`, `console`); how to override that fallback by writing your own `/etc/securetty`; the difference between *interactive* root login (covered here) and *SSH* root login (controlled by `sshd_config PermitRootLogin`); proving the restriction by switching virtual terminals with `chvt` and reading `journalctl -u systemd-logind`; recovery if you lock yourself out
- **Career arcs covered:** RHCSA (the EX200 objective on PAM specifically calls out "restrict root login on tty"), RHCE (Ansible's `pamd` and `lineinfile` modules manage PAM stacks idempotently), SRE (every hardened production host has a documented root-console policy and a runbook for unlocking from rescue), DevOps (CIS Benchmark §5 mandates `pam_securetty` on the login stack), AI/MLOps (multi-tenant GPU boxes restrict root to a single physical console so an SSH compromise cannot grant interactive root)
- **Prerequisite:** Comfortable with `tty`, `who`, switching virtual terminals (`Ctrl+Alt+F2..F6`), and editing files in `/etc/pam.d/`. Has root or `sudo` access on a non-production VM.
- **Time Estimate:** 30 to 45 minutes
- **Difficulty arc:** Task 1 inventory the current state — does `/etc/securetty` exist? · 2 read the `pam_securetty` line in `/etc/pam.d/login` and understand what it does · 3 confirm the built-in fallback list with `strings`/man pages · 4 write your own `/etc/securetty` and watch behavior change · 5 prove the lockout from a second tty · 6 RHCSA-realistic capstone — pin root to `tty6` only

---

## Objective

You will leave this lab able to explain *and demonstrate* exactly which interactive terminals root is allowed to log in from on a Red Hat 9 system, and why. You will read `/etc/pam.d/login`, find the `auth required pam_securetty.so` line, follow it into the PAM module's man page, and learn the RHEL 9-specific subtlety: **the file `/etc/securetty` is no longer shipped by default**, and the module falls back to a built-in list of "secure" tty names. You will then write a tiny custom `/etc/securetty` to override that fallback, prove the new policy works by attempting a root login on a disallowed tty, and document the recovery procedure in case you lock yourself out.

The capstone is an honest, exam-realistic configuration: pin interactive root to `tty6` only, verify from `tty2` that root cannot log in there, then unwind the change cleanly. The lab is honest about scope — `pam_securetty` controls *local interactive* logins through `/etc/pam.d/login`, not SSH. SSH root access is controlled by `PermitRootLogin` in `sshd_config`, and many of the same misconceptions ("I set `pam_securetty` and root can still SSH in") will be addressed and resolved.

The capstone framing: *"You took over a hardened RHEL 9 host. Root is supposed to be reachable only on the physical console (tty6). Configure PAM so a local login attempt from any other tty fails, prove it from `tty2`, then read the audit trail."*

> **Lab safety note:** All edits in this lab are to `/etc/securetty` and (for one optional step) `/etc/pam.d/login`. You will keep a root shell open on `tty1` or via `sudo` the entire time so a misconfiguration cannot lock you out. The final task includes an explicit rollback step.

---

## Concept: `pam_securetty` Is a Login Gate, Not a Network Gate

PAM (Pluggable Authentication Modules) breaks login into a stack of independent checks. Each line in `/etc/pam.d/login` calls one module. `pam_securetty.so` is the first `auth` module in that stack on every Red Hat–family distribution. Its single job: **if the calling user is UID 0 (root), check that the tty the login is happening on is on the "secure" list. Otherwise fail with `PAM_AUTH_ERR` immediately.**

```
   ┌─────────────────────────────────────────────────────────────────┐
   │   Local login on tty3 — login(1) calls PAM                      │
   ├─────────────────────────────────────────────────────────────────┤
   │   /etc/pam.d/login                                              │
   │     auth required pam_securetty.so    ← checks /etc/securetty   │
   │     auth substack  system-auth                                   │
   │     auth include   postlogin                                     │
   │     account required pam_nologin.so                              │
   │     ...                                                          │
   ├─────────────────────────────────────────────────────────────────┤
   │   If user = root and tty NOT in secure list:                    │
   │       return PAM_AUTH_ERR  →  login(1) prints "Login incorrect" │
   │       NO password prompt is even shown.                          │
   └─────────────────────────────────────────────────────────────────┘

   What pam_securetty.so reads, in order:
     1. /etc/securetty   (if it exists)
     2. Built-in fallback list compiled into the module
                          (RHEL 9: tty1..tty11, console, plus a small console set)
```

The crucial RHEL 9 fact: in older Red Hat releases `/etc/securetty` was a shipped file with one tty per line. Starting around RHEL 8 the file is no longer shipped by default, and `pam_securetty` uses its compiled-in fallback. If you want a custom policy you **create** the file. The presence of the file overrides the fallback list completely.

> **Why this matters:** EX200 objectives explicitly include "use PAM to control or restrict root and user access." The simplest, fairest version of that ask is "make sure root cannot log in from random virtual terminals." A two-line edit to a file root has to create is exactly the kind of small, verifiable change the exam loves. And in the field, a junior who tries to "harden root login" by changing `sshd_config` and forgets that someone with physical access can walk up to `tty3` is missing half the threat model.

---

## 📜 Why `pam_securetty` Exists — The Story

Before PAM, login authentication was hard-coded in the `login` binary. To add a new check — "only allow root from the console" — a vendor had to ship a new `login`. That made fine-grained policy difficult, and it made local customization nearly impossible. **Pluggable Authentication Modules**, invented at Sun in 1995 and adopted by Linux as Linux-PAM in 1996, replaced the hard-coded checks with a per-service text-file stack of dynamically loaded `.so` modules. Now every login can be customized site by site without recompiling.

`pam_securetty.so` is one of the oldest PAM modules. Its purpose has not changed in twenty-five years: enforce the policy "interactive root is allowed only from a known, physically-controlled set of terminals." The file it reads — `/etc/securetty` — predates PAM itself; the old BSD `login` binary read the same path. Linux-PAM kept the convention so legacy expectations would continue to work.

The list of "secure" terminals historically included serial consoles, virtual consoles (`tty1`–`tty11`), and the physical text console (`console`). It deliberately *excluded* pseudo-terminals (`pts/*`) — the device files used by SSH, screen, tmux, and graphical terminal emulators — because the threat model is "an attacker who has compromised a service is now sitting on a pty trying to type `root` at a login prompt." Excluding pts means even a network attacker on a privileged shell cannot escalate to a fresh interactive root login through `login(1)`.

In **RHEL 8 and RHEL 9**, Red Hat removed the shipped `/etc/securetty` file but kept the module. The reasoning, documented in upstream PAM commits, is that the modern threat model on multi-user servers has shifted to network attackers, and the built-in fallback already covers the safe defaults. Administrators who want a stricter policy — say, "root only on tty6" — are expected to write their own `/etc/securetty` with exactly the entries they intend to allow. The file's absence does **not** mean root can log in anywhere; the fallback still excludes pts.

> **The point of the story:** `pam_securetty` is a 1990s solution to a problem that has not gone away — physical-console attackers — wrapped in a 2020s pluggable architecture. The mechanism is one PAM line; the policy is one small text file. Knowing both is the RHCSA objective.

---

## 👪 The `pam_securetty` Family — Who Lives There

The "limit root access" family is small. Four files and one PAM directive carry the entire policy.

### Files involved

| Path | Role | Notes |
|---|---|---|
| `/etc/pam.d/login` | The PAM stack consulted by `login(1)` | Contains `auth required pam_securetty.so` near the top |
| `/etc/pam.d/system-auth` | Common auth substack included by many services | Does *not* call `pam_securetty` itself |
| `/etc/securetty` | List of tty device names root may log in on | **Not shipped on RHEL 9** — create it to override the fallback |
| `/lib64/security/pam_securetty.so` | The compiled module | Contains the fallback list when `/etc/securetty` is absent |
| `/etc/ssh/sshd_config` | Where SSH-root policy lives | Completely **separate** from `pam_securetty` — read `PermitRootLogin` |

### Module modes and arguments

| Token | Meaning |
|---|---|
| `auth required pam_securetty.so` | Standard form. Failure aborts the whole `auth` phase. |
| `auth required pam_securetty.so noconsole` | Do not auto-treat the kernel `console` device as secure |
| `auth required pam_securetty.so debug` | Log decisions to `journalctl -u systemd-logind` and `/var/log/secure` |
| `account required pam_nologin.so` | Different module — covered in the next lab — blocks all non-root users when `/etc/nologin` exists |
| `auth sufficient pam_rootok.so` | The *opposite* check: pass automatically if UID 0 (used in `su` to skip the password) |

### Terminals you might list in `/etc/securetty`

| Entry | Where it applies |
|---|---|
| `tty1` … `tty6` | Virtual consoles (`Ctrl+Alt+F1..F6`) |
| `tty7` … `tty11` | More virtual consoles; rarely used on headless servers |
| `console` | The kernel's primary console device |
| `ttyS0` | First serial console (cloud images, IPMI SoL) |
| `ttyAMA0` | ARM serial console |
| `hvc0` | Hypervisor virtual console (KVM/Xen) |

> **The point of the family tree:** One module, one file, one PAM stack. Add a line to the file to allow a tty; delete it to disallow. There is no daemon to restart and no service to enable.

---

## 🔬 The Anatomy of the `pam_securetty` Line — In One Diagram

```
# /etc/pam.d/login   (excerpt — RHEL 9 default)
auth   required   pam_securetty.so
│      │          │
│      │          └─ The shared object loaded from /lib64/security/
│      └─ Control flag: "required" — failure means the whole stack fails,
│         but later modules still run (so attacker cannot deduce which
│         step failed by timing). For the equivalent fast-fail you'd use
│         "requisite" instead, but Red Hat's default is "required".
└─ Phase: "auth" — runs at the very start, before any password prompt.

What the module does at runtime:
  1. PAM calls pam_sm_authenticate() inside pam_securetty.so.
  2. The module reads the PAM item PAM_USER. If it's NOT root, return
     PAM_SUCCESS immediately. (pam_securetty only restricts UID 0.)
  3. Read the PAM item PAM_TTY (the tty login(1) set, e.g. "tty3").
  4. Open /etc/securetty.
       - If the file exists: a line-by-line match against PAM_TTY.
       - If the file does NOT exist: use the built-in fallback list.
  5. If PAM_TTY appears in the consulted list → PAM_SUCCESS.
     Otherwise → PAM_AUTH_ERR.

A PAM_AUTH_ERR at this point means login(1) prints "Login incorrect"
and the user is never even prompted for a password.
```

> **Reading rule:** `pam_securetty` is purely a tty filter. It does not look at the user's password, it does not look at SSH, it does not look at sudo. It only asks: "Is this UID 0, and is PAM_TTY on the list?"

---

## 📚 Root-Login PAM Reference Table

| Task | Command | Notes |
|---|---|---|
| Show the active PAM stack for `login(1)` | `cat /etc/pam.d/login` | The line `auth required pam_securetty.so` is the gate |
| Show whether `/etc/securetty` exists | `ls -l /etc/securetty 2>/dev/null \|\| echo "absent (fallback in effect)"` | On RHEL 9, default is *absent* |
| See the module's compiled-in fallback | `man pam_securetty` | The default list is documented; do not read the binary |
| List currently allowed ttys (effective) | `cat /etc/securetty 2>/dev/null \|\| man pam_securetty \| sed -n '/CONFIGURATION/,/^[A-Z]/p'` | When file is absent, fall back to docs |
| Switch to a virtual terminal | `Ctrl+Alt+F2` (on the physical console) | Or `sudo chvt 2` from another shell |
| See which tty your current shell is on | `tty` | Outputs e.g. `/dev/tty3` or `/dev/pts/0` |
| See recent login attempts | `journalctl -u systemd-logind --since "10 minutes ago"` | The denial event lands here |
| See PAM authentication events | `tail -n 30 /var/log/secure` | Look for `pam_securetty(login:auth): access denied` |
| Confirm SSH root policy is independent | `grep '^PermitRootLogin' /etc/ssh/sshd_config` | This is the SSH-side switch, not `pam_securetty` |
| Recovery if locked out | Reboot, enter rescue (`systemd.unit=rescue.target` on kernel line) | Always possible with physical/console access |

> **Rule one of `pam_securetty`:** Absence of `/etc/securetty` does **not** mean "anywhere allowed." It means "the built-in fallback list applies." Creating the file is how you override that fallback.

---

## 🎯 Career Pathway Sidebar

| Level | Why this lab matters |
|---|---|
| **RHCSA candidate** | "Use PAM to control or restrict root access" is in the objective list verbatim. A two-line config and a verification command answers the prompt in 90 seconds. |
| **RHCE candidate** | Ansible's `community.general.pamd` module surgically inserts/removes lines like `auth required pam_securetty.so`. Knowing what the line *does* is what makes the playbook idempotent. |
| **SRE / Platform** | Postmortem: "Why couldn't the on-call log in to the console after the power blip?" — someone left a hardened `/etc/securetty` that did not include `ttyS0`, the IPMI serial console. |
| **DevOps** | CIS Benchmark §5.5 (Ensure root login is restricted to system console) is an automated audit item. Your hardening role drops in the exact `/etc/securetty` from this lab. |
| **AI / MLOps** | GPU hosts in multi-tenant clusters typically allow root only on a single tty (or no tty — root login disabled entirely, sudo-only). This module is half of that policy. |

---

## 🔧 The 6 Tasks

> Six exam-realistic phases that build the **inventory → understand → configure → verify → audit → recover** habit for `pam_securetty`.

---

### Task 1 — Inventory the current state of `pam_securetty` and `/etc/securetty`

**Purpose:** Before you change anything, document what RHEL 9 ships out of the box: the `pam_securetty` line in `/etc/pam.d/login` is present and active, but the file `/etc/securetty` is **absent**, so the module's built-in fallback list is in effect.

```bash
sudo -i
cd /root

cat /etc/pam.d/login | head -n 5
grep -n pam_securetty /etc/pam.d/login

ls -l /etc/securetty 2>/dev/null || echo "absent (fallback in effect)"
rpm -qf /usr/lib64/security/pam_securetty.so
tty
who
```

**Human-Readable Breakdown:** Show the top of `/etc/pam.d/login` (so you can see the auth stack), grep for the exact `pam_securetty` line and its line number, confirm whether `/etc/securetty` exists, identify which RPM ships the module, and finally print which tty you are on right now so you know which terminal you can use to test from.

**Reading it left to right:** `head -n 5 /etc/pam.d/login` shows the first few lines, which is where `auth required pam_securetty.so` lives on RHEL. `grep -n` adds the line number for documentation. `ls -l /etc/securetty 2>/dev/null || echo ...` either prints the file's listing (if shipped) or prints the fallback message (if absent — the RHEL 9 default). `rpm -qf` resolves the `.so` to the owning package, which is `pam`. `who` shows everyone logged in and which tty they are on.

**The story:** RHCSA tasks always begin with "before you change anything, see what is there." On RHEL 9 you should expect the file to be absent — and you should be able to *explain* what that means. A junior who panics ("the file is missing! the security is broken!") will produce a worse system; the senior recognizes the fallback and writes the file deliberately.

**Expected output:**

```text
#%PAM-1.0
auth       substack     system-auth
auth       include      postlogin
account    required     pam_nologin.so
account    include      system-auth
2:auth       required     pam_securetty.so
absent (fallback in effect)
pam-1.5.1-19.el9.x86_64
/dev/tty1
NAME     LINE         TIME             COMMENT
root     tty1         2026-05-26 13:45
root     pts/0        2026-05-26 13:46 (192.168.122.1)
```

*(The exact contents and line numbers may differ slightly per minor release. The presence of the `pam_securetty.so` line and the absence of `/etc/securetty` are the two facts that matter.)*

**Switches**

| Token | Meaning |
|---|---|
| `head -n 5 FILE` | First 5 lines |
| `grep -n PATTERN FILE` | Match, with line numbers |
| `2>/dev/null \|\| echo ...` | If the previous command errored (here: file not found), print fallback text |
| `rpm -qf FILE` | Which package owns this file |
| `tty` | Print the current shell's controlling tty |
| `who` | Show all logged-in sessions and their ttys |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `pam_securetty` line is not present | You are on a stripped or custom build; re-install `pam` |
| `rpm -qf` says "not owned by any package" | The `.so` was replaced manually — re-install `pam` |
| `tty` prints `not a tty` | You are inside a non-interactive shell (cron, ssh -T) — open an actual terminal |
| `ls /etc/securetty` shows the file exists | An admin already created one — read its contents and back it up before editing |

---

### Task 2 — Read what `pam_securetty.so` actually allows by default

**Purpose:** Confirm — from documentation, not guesswork — what tty names are on the module's built-in fallback list when `/etc/securetty` is absent. Knowing the fallback is what lets you reason about behavior before you write your own file.

```bash
sudo -i
man -P cat pam_securetty | sed -n '/^DESCRIPTION/,/^FILES/p'

echo
echo "--- what the manpage says about /etc/securetty ---"
man -P cat pam_securetty | sed -n '/^FILES/,/^SEE ALSO/p'
```

**Human-Readable Breakdown:** Use `man` (piped through `cat` with `-P` so it doesn't paginate) and pull the `DESCRIPTION` and `FILES` sections of the `pam_securetty` manpage. The `DESCRIPTION` explains the module's behavior; the `FILES` section explicitly notes that `/etc/securetty` is read if present and that there is a compiled-in default otherwise.

**Reading it left to right:** `man -P cat` runs `man` but pipes its output through `cat` instead of `less`, so the result is plain text you can grep. `sed -n '/PATTERN1/,/PATTERN2/p'` prints only the lines from `PATTERN1` to `PATTERN2`, giving you a focused excerpt. The two sed ranges pull out the prose paragraphs you actually need to read.

**The story:** Real sysadmins do not memorize PAM module behavior. They read the manpage. The RHCSA exam puts a copy of every relevant manpage on the test machine for precisely this reason. Practice the *workflow* of pulling the right section out of `man` — that workflow will save you in any unfamiliar PAM situation, not just this one.

**Expected output:**

```text
DESCRIPTION
       pam_securetty is a PAM module that allows root logins only if the user is logging
       in on a "secure" tty, as defined by the listing in /etc/securetty.

       pam_securetty also checks to make sure that /etc/securetty is a plain file and not
       world writable. It will also allow root logins on the tty specified with console=
       on the kernel command line and on devices in /etc/securetty.

       This module has no effect on non-root users and requires that the application fills
       in the PAM_TTY item correctly.

       For canonical usage, should be listed as a required authentication method before any
       sufficient authentication methods.

--- what the manpage says about /etc/securetty ---
FILES
       /etc/securetty
           File listing terminal names where root is allowed to login. If the file does not
           exist, the module will instead use a compiled-in list of safe defaults: tty1
           through tty11, plus console, ttyS0, and the kernel console device.

SEE ALSO
       securetty(5), pam.conf(5), pam.d(5), pam(7)
```

*(Wording varies slightly with minor releases. The two facts to extract: pty devices are **not** on the fallback list, and the file's mere presence overrides the fallback completely.)*

**Switches**

| Token | Meaning |
|---|---|
| `man -P cat NAME` | Format `man` output through `cat` (no pager) |
| `sed -n '/A/,/B/p'` | Print only lines from A to B inclusive |
| `pam_securetty(8)` | Section 8 manpage for the module |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `man pam_securetty: No manual entry` | Install `pam-docs` — `sudo dnf install -y pam-docs` |
| The DESCRIPTION section is empty | Manpage version mismatch — `dnf reinstall pam-docs` |
| You see `pam_securetty(5)` instead of `(8)` | Both exist on some distros — `(8)` is the module, `(5)` is the file format |

---

### Task 3 — Create your own `/etc/securetty` and watch behavior change

**Purpose:** Override the built-in fallback by writing an explicit `/etc/securetty`. Start permissive (allow `tty1` through `tty6`) so you do not lock yourself out, then verify the file's mode and ownership.

```bash
sudo -i

if [ -f /etc/securetty ]; then
    cp -a /etc/securetty /root/securetty.backup
fi

cat > /etc/securetty <<'EOF'
tty1
tty2
tty3
tty4
tty5
tty6
console
ttyS0
EOF

chmod 0600 /etc/securetty
chown root:root /etc/securetty

ls -l /etc/securetty
cat /etc/securetty
```

**Human-Readable Breakdown:** If the file already exists, back it up. Then write a new `/etc/securetty` containing `tty1` through `tty6`, the kernel `console`, and the first serial console `ttyS0`. Set the file mode to `0600` and ownership to `root:root` (the module refuses to honor a world-writable securetty). Verify with `ls -l` and `cat`.

**Reading it left to right:** The `if [ -f ... ]; then cp -a ...` block preserves any pre-existing file so the lab is reversible. The `cat > FILE <<'EOF' ... EOF` heredoc writes the file in one shell builtin call, no editor required. `chmod 0600` matches Red Hat's convention for security-relevant `/etc` files — readable only by root. `chown root:root` ensures the module accepts the file (it will silently ignore one owned by anyone else).

**The story:** Writing this file is the entire "configuration" of `pam_securetty`. There is no service to restart, no daemon to reload, no signal to send — `login(1)` opens `/etc/securetty` fresh on every login attempt. That makes this one of the most satisfying PAM tasks: change a text file, immediately observe new policy.

**Expected output:**

```text
-rw-------. 1 root root 38 May 26 13:50 /etc/securetty
tty1
tty2
tty3
tty4
tty5
tty6
console
ttyS0
```

**Switches**

| Token | Meaning |
|---|---|
| `cat > FILE <<'EOF' ... EOF` | Heredoc, writes file without an editor |
| `chmod 0600` | Owner read/write, no group/world access |
| `chown root:root` | Owner and group both root |
| `cp -a SRC DST` | Archive-mode copy (preserves mode, owner, timestamps) |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `cat: write error: No space left on device` | `/etc` filesystem is full — investigate |
| File permissions are `0644` after `chmod 0600` | A umask or selinux issue — re-run `chmod 0600` explicitly |
| You typed `pts/0` into the file | Remove it. `pam_securetty` is for *real* ttys, not pseudo-ttys |
| SELinux denies the write | Run `restorecon -v /etc/securetty` to re-label the new file |

---

### Task 4 — Tighten the policy to `tty6` only and verify which terminals are now refused

**Purpose:** Narrow `/etc/securetty` down to a single allowed terminal. Keep a root session open on `tty1` (or via `sudo` from a normal user on `pts/0`) so you can recover, then test root login from `tty2`.

```bash
sudo -i

cat > /etc/securetty <<'EOF'
tty6
EOF
chmod 0600 /etc/securetty
chown root:root /etc/securetty

echo "Effective allow-list:"
cat /etc/securetty
echo

echo "Switch to tty2 with Ctrl+Alt+F2, attempt: login as root"
echo "Then return here with Ctrl+Alt+F1 and run:"
echo "  tail -n 5 /var/log/secure"
```

**Human-Readable Breakdown:** Replace `/etc/securetty` with a one-line file containing just `tty6`. Print the resulting allow-list for the record. Then — from the safety of `tty1` where you are still logged in as root — instruct yourself to switch to `tty2` and attempt to log in as root. The attempt should be refused immediately, with no password prompt.

**Reading it left to right:** A fresh heredoc overwrites the file. The chmod/chown is repeated because the heredoc creates a new inode and inherits the umask. Then the script *narrates* the manual verification step (switch tty, attempt login, return, check `/var/log/secure`) — this is the moment a real human action is required.

**The story:** This is the moment `pam_securetty` stops being abstract. You are root on `tty1`, you walk over (mentally) to `tty2`, you type `root` at the prompt, and `login` says `Login incorrect` immediately. No password prompt. PAM rejected the username before the password was even asked. That is the policy working exactly as designed. Crucially, your existing session on `tty1` is untouched — `pam_securetty` only gates *new* logins.

**Expected output:**

```text
Effective allow-list:
tty6
Switch to tty2 with Ctrl+Alt+F2, attempt: login as root
Then return here with Ctrl+Alt+F1 and run:
  tail -n 5 /var/log/secure
```

*(After the manual login attempt on tty2, `/var/log/secure` should contain a line like:)*

```text
May 26 13:55:01 host login[12345]: pam_securetty(login:auth): access denied: tty 'tty2' is not secure !
May 26 13:55:01 host login[12345]: FAILED LOGIN 1 FROM tty2 FOR root, Authentication failure
```

**Switches**

| Token | Meaning |
|---|---|
| `Ctrl+Alt+F2` | Switch to virtual terminal 2 (physical console only) |
| `Ctrl+Alt+F1` | Return to terminal 1 |
| `tail -n 5 FILE` | Last 5 lines of FILE |
| `/var/log/secure` | RHEL's auth log; PAM messages land here |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Root *was* allowed in on `tty2` | The file is empty, owned wrong, or world-writable — re-check `ls -l /etc/securetty` |
| No log line in `/var/log/secure` | `rsyslog` may not be running; try `journalctl -u systemd-logind` |
| `Ctrl+Alt+F2` does nothing | You are inside a graphical session that intercepts the keys — use `sudo chvt 2` from a shell |
| You locked yourself out | Boot to rescue (kernel arg `systemd.unit=rescue.target`), remount rw, edit `/etc/securetty` |

---

### Task 5 — Prove SSH root login is *not* affected by `pam_securetty`

**Purpose:** Hard-prove the boundary of `pam_securetty`. SSH does not go through `/etc/pam.d/login`; it uses `/etc/pam.d/sshd`, which does **not** include `pam_securetty`. Therefore `PermitRootLogin` in `sshd_config` is what controls SSH-root, not this file.

```bash
sudo -i

grep -n pam_securetty /etc/pam.d/sshd || echo "pam_securetty is NOT in the sshd stack"

grep -n '^PermitRootLogin\|^#PermitRootLogin' /etc/ssh/sshd_config
sshd -T 2>/dev/null | grep -i permitrootlogin

echo
echo "Now attempt: ssh root@127.0.0.1   (from another shell, as a normal user)"
echo "Result depends on PermitRootLogin, NOT on /etc/securetty."
```

**Human-Readable Breakdown:** Search for `pam_securetty` in the SSH PAM stack — it is not there. Show the effective value of `PermitRootLogin` from the SSH config and from `sshd -T` (which prints the live, effective configuration including defaults). Conclude that SSH root access is governed by a separate switch.

**Reading it left to right:** `grep -n pam_securetty /etc/pam.d/sshd` searches the SSH PAM stack; the absence of any match confirms `pam_securetty` is not consulted on SSH logins. `sshd -T` prints the merged effective config, including settings that exist only as defaults; `grep permitrootlogin` filters to the relevant line. The two checks together prove the boundary.

**The story:** This is the misunderstanding that produces tickets. Junior admin sets `pam_securetty` to allow only `tty6`, then "tests" by SSHing in as root and concludes the lock-down works. It does not — they got in because `sshd_config` still says `PermitRootLogin yes`. The mature configuration sets *both* — `pam_securetty` for the physical console, `PermitRootLogin no` for the network. They are independent levers on the same root-access switchboard.

**Expected output:**

```text
pam_securetty is NOT in the sshd stack
38:#PermitRootLogin prohibit-password
permitrootlogin prohibit-password
Now attempt: ssh root@127.0.0.1   (from another shell, as a normal user)
Result depends on PermitRootLogin, NOT on /etc/securetty.
```

**Switches**

| Token | Meaning |
|---|---|
| `grep -n PATTERN FILE \|\| echo MSG` | Search and print MSG if nothing matched |
| `sshd -T` | Print the live effective sshd configuration |
| `PermitRootLogin no` | Block SSH root entirely |
| `PermitRootLogin prohibit-password` | Allow SSH root with public key only (RHEL 9 default) |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `sshd -T` says `command not found` | Use `/usr/sbin/sshd -T` with absolute path |
| SSH root login worked anyway | Expected — `pam_securetty` is not in the SSH stack; set `PermitRootLogin no` to block SSH root |
| `grep -n pam_securetty /etc/pam.d/sshd` returned a match | A custom config has added it — read that file carefully before editing |
| `pam_securetty` *is* called for SSH but always passes | The PAM_TTY item for SSH is usually `ssh` or `(none)` — the module shortcircuits because it cannot match a real tty |

---

### Task 6 — Capstone: pin root to `tty6` only and produce a verifiable artifact

**Task statement:** *"Configure `pam_securetty` so that root may interactively log in only on `tty6`. Save a copy of the resulting `/etc/securetty` to `/root/securetty.proof.txt`, save the effective PAM line from `/etc/pam.d/login`, attempt a root login from `tty2`, and confirm the denial appears in `/var/log/secure`. Then revert."*

**Purpose:** Execute the end-to-end policy change as an exam grader would expect, produce a single artifact that documents both the configuration and the verification, then unwind the change cleanly so the lab leaves the system in its original state.

```bash
sudo -i
cd /root

cat > /etc/securetty <<'EOF'
tty6
EOF
chmod 0600 /etc/securetty
chown root:root /etc/securetty
restorecon -v /etc/securetty 2>/dev/null || true

{
  echo "=== /etc/pam.d/login (pam_securetty line) ==="
  grep -n pam_securetty /etc/pam.d/login
  echo
  echo "=== /etc/securetty contents ==="
  cat /etc/securetty
  echo
  echo "=== ls -l /etc/securetty ==="
  ls -l /etc/securetty
} > /root/securetty.proof.txt

echo "Now attempt: from tty2 (Ctrl+Alt+F2), login as root."
echo "Then from tty1 run:"
echo "  grep pam_securetty /var/log/secure | tail -n 3 >> /root/securetty.proof.txt"

test -s /root/securetty.proof.txt && echo "VERIFY: proof file exists and is non-empty"
```

**Human-Readable Breakdown:** Write `/etc/securetty` containing only `tty6`. Lock down its mode and ownership. Re-label for SELinux. Then assemble a single proof file at `/root/securetty.proof.txt` containing the PAM line, the securetty contents, and the file metadata. Finally, attempt the disallowed login from `tty2` and append the matching denial line from `/var/log/secure` to the proof file.

**Layer stack you built:**

```text
/root/securetty.proof.txt             <- the artifact a grader reads
  ├── /etc/pam.d/login line             <- proves pam_securetty is active
  ├── /etc/securetty contents            <- proves tty6-only policy
  ├── ls -l /etc/securetty              <- proves mode 0600, root:root
  └── /var/log/secure denial line        <- proves enforcement happened
                                           (appended after the tty2 attempt)
```

**The story:** This is the **canonical RHCSA hardening artifact**. The grader can verify each of four facts from one file. There is no service restart and no daemon to reload — `login` re-reads `/etc/securetty` on every attempt. Once you confirm the denial, revert by removing the file (so the fallback list is back in effect) or by restoring the backup you took in Task 3.

**Expected verification output:**

```text
=== /etc/pam.d/login (pam_securetty line) ===
2:auth       required     pam_securetty.so

=== /etc/securetty contents ===
tty6

=== ls -l /etc/securetty ===
-rw-------. 1 root root 5 May 26 14:02 /etc/securetty

May 26 14:03:11 host login[23456]: pam_securetty(login:auth): access denied: tty 'tty2' is not secure !
May 26 14:03:11 host login[23456]: FAILED LOGIN 1 FROM tty2 FOR root, Authentication failure
VERIFY: proof file exists and is non-empty
```

**Cleanup**

```bash
sudo -i

if [ -f /root/securetty.backup ]; then
    cp -a /root/securetty.backup /etc/securetty
    chmod 0600 /etc/securetty
    chown root:root /etc/securetty
    restorecon -v /etc/securetty 2>/dev/null || true
else
    rm -f /etc/securetty
fi

rm -f /root/securetty.proof.txt /root/securetty.backup
ls -l /etc/securetty 2>/dev/null || echo "removed — fallback list is now in effect"
exit
```

**Troubleshoot**

| Symptom | Fix |
|---|---|
| The proof file is empty | The redirection block was inside a subshell that lost stdout — re-run as shown |
| `/var/log/secure` has no `pam_securetty` line | `rsyslog` may not be running — check `systemctl status rsyslog` and try `journalctl _COMM=login` |
| You locked yourself out of the console | Boot to rescue (`systemd.unit=rescue.target` on kernel cmdline), mount rw, remove `/etc/securetty` |
| `restorecon` complained | Harmless if SELinux is permissive; otherwise `setenforce 0` and re-label |
| You deleted the file but root still cannot log in on `tty2` | Fallback list applies; `tty2` should be allowed — confirm with `journalctl -u systemd-logind` |

---

## 🔍 root-Login Decision Guide

```
Need to restrict where root can log in?
  │
  ├── "Restrict interactive (tty) logins"
  │       └── ✅ Edit /etc/securetty  (this lab)
  │             ├─ File absent       → built-in fallback (tty1..tty11 + console)
  │             ├─ File present      → only entries listed
  │             └─ Must be mode 0600, root:root
  │
  ├── "Restrict SSH logins"
  │       └── ✅ Edit /etc/ssh/sshd_config → PermitRootLogin
  │             ├─ no                     → block all SSH root
  │             ├─ prohibit-password      → keys only (RHEL 9 default)
  │             └─ yes                    → password allowed (avoid)
  │
  ├── "Restrict console + SSH + su"
  │       └── ✅ Set BOTH the above PLUS:
  │             ├─ auth required pam_wheel.so use_uid  in /etc/pam.d/su
  │             └─ Confirm only members of `wheel` can `su -`
  │
  ├── "Disable root login completely (sudo-only)"
  │       └── ✅ passwd -l root  +  PermitRootLogin no  +  /etc/securetty empty
  │
  └── "Allow root only on serial console for remote IPMI"
          └── ✅ /etc/securetty contains only `ttyS0`
                + PermitRootLogin no
                + Serial console enabled in GRUB
```

---

## ✅ Lab Checklist (6 Tasks)

- [ ] 01 Inventory `/etc/pam.d/login`, confirm `pam_securetty` is present, and confirm `/etc/securetty` is absent on stock RHEL 9
- [ ] 02 Read the `pam_securetty(8)` manpage and identify the compiled-in fallback list
- [ ] 03 Create `/etc/securetty` with `tty1..tty6 console ttyS0`, mode `0600`, owner `root:root`
- [ ] 04 Narrow `/etc/securetty` to `tty6` only, attempt login from `tty2`, and confirm the denial in `/var/log/secure`
- [ ] 05 Confirm `pam_securetty` is not in the SSH PAM stack and that `PermitRootLogin` is the SSH-side lever
- [ ] 06 Produce `/root/securetty.proof.txt` containing the PAM line, file contents, `ls -l`, and the denial log; then revert

---

## ⚠️ Common Pitfalls

| Mistake | Symptom | Fix |
|---|---|---|
| Assumed `pam_securetty` blocks SSH root | SSH root still works | It does not — set `PermitRootLogin no` in `sshd_config` |
| Made `/etc/securetty` world-readable | Module silently ignores it | `chmod 0600`, `chown root:root` |
| Listed `pts/0` in `/etc/securetty` | No effect | `pam_securetty` is for real ttys; pts is never on the secure list anyway |
| Deleted `/etc/securetty` and expected lockdown | Anyone (well, root) can log in on the fallback list | Absence reverts to the compiled-in default — create the file to override |
| Edited `/etc/pam.d/login` and forgot a syntax error | Local login broken entirely | Boot to rescue and revert; never edit PAM without a second open root shell |
| Used `tty` in lowercase incorrectly | The file ignores `Tty1` | Entries are case-sensitive; use lowercase `tty1` |
| Used `/dev/tty1` instead of `tty1` | The file ignores the entry | The module compares against `PAM_TTY`, which is the bare name |
| Forgot SELinux relabel after a heredoc-create | `pam_securetty` cannot read the file in enforcing mode | `restorecon -v /etc/securetty` |
| Locked yourself out by emptying the file | All local root logins refused | Boot to rescue and restore from `/root/securetty.backup` |
| Confused with `pam_listfile` | Different module, different syntax | `pam_listfile` is Lab 77 — it generalizes the idea to *any* user |

---

## 🎯 Career & Interview Strategy

**RHCSA candidate**
- Expect a task like "configure the system so root may only log in on tty5." The answer is a three-line `/etc/securetty` change plus a verification from another tty. Practice the heredoc until it is muscle memory.

**RHCE candidate**
- Ansible `community.general.pamd` lets you assert that `auth required pam_securetty.so` exists in `/etc/pam.d/login`. Pair with `ansible.builtin.copy` for `/etc/securetty`. The playbook should be idempotent and include a handler that does *not* restart anything (no daemon to reload).

**SRE / Platform interview**
- "How would you ensure root can only be reached via the IPMI serial console in an emergency?" → `/etc/securetty` contains only `ttyS0`, `PermitRootLogin no` in `sshd_config`, `passwd -l root` so the password is locked (key auth only on the serial console). Three layers.

**DevOps**
- CIS Benchmark hardening roles drop in a deterministic `/etc/securetty`. Your release process must include console-recovery instructions because a misconfig can lock the runner.

**AI / MLOps**
- Shared GPU hosts in research clusters typically allow root only on a single console for break-glass debugging. `pam_securetty` is half of that policy; the other half is `passwd -l root` plus sudo-only access for non-root admins.

---

## 🔗 Related Labs

| Lab | Connection |
|---|---|
| Lab — Use PAM to Limit User Access | The non-root half: `pam_nologin.so` + `/etc/nologin` |
| Lab — Restrict Service Access by User List | The generalization: `pam_listfile.so` against any user list |
| Lab — PAM Config Files | Tour of `/etc/pam.d/` and the `auth account password session` phases |
| Lab — Password Complexity (pwquality) | The `password` phase of the same PAM stack |
| Lab — SSH Key-Based Auth | The other half of root-login policy on real servers |
| Lab — TCP Wrappers (`hosts.allow` / `hosts.deny`) | The IP-layer companion to PAM's user-layer policy |

---

## 👤 Author

**Kelvin R. Tobias**
[kelvinintech.com](https://kelvinintech.com) · [GitHub](https://github.com/kelvintechnical) · [LinkedIn](https://www.linkedin.com/in/kelvin-r-tobias-211949219)

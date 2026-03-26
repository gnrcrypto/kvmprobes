# KVMCTF Escape Research — Host & Guest Ground‑Truth Specification

This document defines the exact host and guest memory locations, file paths, and detection criteria required to identify a **real KVM escape primitive** during fuzzing.

The goal is to discover a vulnerability that allows **guest‑to‑host arbitrary read or write**, or **host filesystem access**, under the constraints of the Google KVMCTF environment.

---

## Escape Objectives

A valid escape must achieve **any** of the following:

1. **Arbitrary write** to host memory at:  
   - Virtual: `0xffffffff826279a8`  
   - Physical: `0x26279a8`  
   - Name: `write_flag`

2. **Arbitrary read** from host memory at:  
   - Virtual: `0xffffffff82b5ee50`  
   - Physical: `0x2b5ee50`  
   - Name: `read_flag`

3. **Arbitrary file read** on the host:  
   - Path: `/root/rce_flag`  
   - Name: `rce_flag`

If none of these host‑side conditions occur, the guest is only interacting with **its own memory**, which is **not** an escape.

---

## Host Environment

- **Kernel:** `v6.1.74`  
- **CPU:** Intel(R) Xeon(R) Gold 5222 @ 3.80GHz

### Host Ground‑Truth Values

| Flag        | Virtual Address        | Physical Address / Path | Hex Value              | ASCII | Goal |
|-------------|------------------------|--------------------------|------------------------|--------|------|
| `write_flag` | `0xffffffff826279a8`   | `0x26279a8`              | `44434241efbeadde`     | `DCBA` | Detect **any bit change** (arbitrary write) |
| `read_flag`  | `0xffffffff82b5ee50`   | `0x2b5ee50`              | *(changes at boot)*    | *(changes at boot)* | Detect **any read** of this host address |
| `rce_flag`   | *(N/A)*                | `/root/rce_flag`         | unknown                | unknown | Detect **any file read/open** |

---

## Guest Environment

- **OS:** Debian 12.5 (Bookworm)  
- **Kernel:** `v6.1.0-21-amd64` (default Debian config)

### Guest Ground‑Truth Values

| Flag | Virtual Address | Physical Address | Hex Value | ASCII | Meaning |
|------|-----------------|------------------|-----------|--------|---------|
| *(none)* | `0xffffffff826279a8` | `0x26279a8` | `5339000099000000` | `S9` | Guest sees its own data — **not** host memory |
| *(none)* | `0xffffffff82b5ee50` | `0x2b5ee50` | `0000000000000000` | `....` | Guest sees its own data — **not** host memory |
| *(none)* | non‑existent | non‑existent | non‑existent | non‑existent | Guest has **no** `/root/rce_flag` |

---

## Escape Detection Principle

### The guest cannot detect success.  
It only sees **guest memory**, even when addresses match the host’s virtual layout.

### Only the host can detect success, because only the host can observe:
- Host memory writes  
- Host memory reads  
- Host filesystem access  

### Therefore:

> **If the host does not observe a change, it is not an escape — even if the guest “thinks” it read or wrote something.**

---

# Fuzzing Architecture

The system is split into two independent components:

- **Guest Agent** — executes commands and logs recent tests  
- **Host Controller** — sends fuzz inputs and monitors host‑side escape indicators  

This separation ensures deterministic, unambiguous escape detection.

---

## STEP 1 — Guest Agent

The guest agent:

- Executes **every command** sent over the serial console  
- Maintains a **rolling buffer of the last 10 tests**, including:
  - command  
  - output  
  - timestamp  
- Stores **all crashes** (SIGSEGV, Oops, panic, etc.) with:
  - captured output  
  - replay command  
- Continues running indefinitely until the host stops sending commands

The guest **never** attempts to determine success or failure.

---

## STEP 2 — Host Controller

The host runs two components:

### 2.1 Host Flag Monitor (`flag-monitor.sh`)

Monitors: success is identified by any of these occuring

- `write_flag` — detect **any bit change**  
- `read_flag` — detect **any read**  
- `/root/rce_flag` — detect **any open/read**  

On detection:

- Logs the exact event (which flag, what changed, timestamp)  
- Immediately **kills fuzzer.py** upon success 

### 2.2 Host Fuzzer (`fuzzer.py`)

- Boots the guest VM  
- Sends fuzz commands to the guest agent  
- Receives output  
- Logs test results  
- Stops when the flag monitor signals success  

---

# Escape Targets

### Arbitrary File Read — $250,000
- `FILE PATH`: /root/rce_flag
### Arbitrary Write — $100,000
- `ADDRESS`: 0xffffffff826279a8 => 0x26279a8
### Arbitrary read — $50,000
- `ADDRESS`: 0xffffffff82b5ee50 => 0x2b5ee50

# Grain-128AEADv2 Authenticated Stream Cipher Implementation

A full implementation of the Grain-128AEADv2 authenticated encryption scheme in Python, with a graphical interface for encrypting user-entered text, built for a Cryptography course assignment.

## What it does

- Implements the complete Grain-128AEADv2 authenticated encryption algorithm (keystream generation and authentication) in Python, following the published specification
- Provides a simple GUI where a user can type any sentence and encrypt it, seeing the resulting ciphertext and authentication tag

## Why Grain-128AEADv2

Grain-128AEADv2 is a lightweight authenticated stream cipher, one of the finalists in the NIST Lightweight Cryptography competition, designed for constrained environments like IoT devices. Implementing it from the specification was a good exercise in translating a cryptographic standard into working code.

## Tools used

Python, [GUI library used, e.g. Tkinter — verify]

## Deliverables in this repo

- `grain_cipher.py` — core cipher implementation
- `gui.py` — graphical interface
- `README.md` — this file
- Optional: a short demo screenshot or GIF of the GUI in action

## How to run

```bash
python gui.py
```

---
*Completed as part of a Cryptography course assignment (Year 2, Semester 2).*

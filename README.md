# Dipper

A highly experimental pure rust DPI engine.

## Rationale

nDPI exists but it's all C and there's a lot of macros, it's hard to use cleanly
from rust.

Commercial DPI systems exist, but are prohibitivley expensive.

Alternative "Kind of DPI" systems like Suricata exist and are great, but are
only part rust.

## Tools used

- Nom is used extensivley in order to parse wire formats.
- Etherparse is used to "chunk" packets into their various components.


## Goals

### Short Term

- Functional offline packet inspection.
- DNS, ICMP, HTTP, maybe SSH parsing and inspection.
- Standardised output format.

### Long Term

- Online analysis
- Plugin system?

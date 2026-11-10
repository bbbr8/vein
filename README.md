# Vein

`python vein_candidates.py examples/candidates.json` evaluates proposed schemas
against bounded hexadecimal fixtures, exact expected values, byte anchors and
expected parse failures. Diagnostics and full-input/schema hashes give a model
concrete refinement feedback. Decoded-leaf coverage exposes undecoded byte ranges;
schemas matching the fixtures retain that finite scope. The command calls no
model and never writes to supplied binary inputs.

A declarative binary format language. Each decoded field carries its byte offset, size and type. Bundled schemas cover PNG, JPEG, ZIP and SQLite headers. Python standard library.

    python vein.py check specs/png.vein
    python vein.py parse png image.png --json
    python vein.py --selftest

Supply your own input file for parse. The self-test constructs its own bytes.

## Compare two binaries

    python vein.py diff png before.png after.png

The result identifies both complete inputs by SHA-256 and size, and reports added, removed, modified or relocated decoded leaves with both byte anchors. Paths match fields by schema name and array elements by index. Inserting an element can change later index matches. Bytes outside the decoded fields still contribute to the file hashes.

## Evaluation hardening

Candidate packets accept `max_items` (1..100000, default 10000). Array/depth limits report `EVALUATION_LIMIT` and cannot pass a negative fixture. Even an `until eof_or_fail` array stopped by its item limit remains incomplete. A fixture can set `require_full_coverage:true` to reject undecoded byte ranges; coverage measures bytes touched by leaves, not bit coverage or meaning.

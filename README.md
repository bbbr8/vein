# Vein

A declarative binary format language. Each decoded field carries its byte offset, size and type. Bundled schemas cover PNG, JPEG, ZIP and SQLite headers. Python standard library.

    python vein.py check specs/png.vein
    python vein.py parse png image.png --json
    python vein.py --selftest

Supply your own input file for parse. The self-test constructs its own bytes.

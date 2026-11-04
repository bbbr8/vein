# Vein

A declarative binary format language. Each decoded field carries its byte offset, size and type. Bundled schemas cover PNG, JPEG, ZIP and SQLite headers. Python standard library.

    python vein.py check specs/png.vein
    python vein.py parse png image.png --json
    python vein.py --selftest

Supply your own input file for parse. The self-test constructs its own bytes.

## Compare two binaries

    python vein.py diff png before.png after.png

The result identifies both complete inputs by SHA-256 and size, and reports added, removed, modified or relocated decoded leaves with both byte anchors. Paths match fields by schema name and array elements by index. Inserting an element can change later index matches. Bytes outside the decoded fields still contribute to the file hashes.

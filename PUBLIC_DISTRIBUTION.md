# Public local-only distribution

Run these tools on a computer you control through their command line or local
Python modules. No HTTP server, hosted endpoint or deployment configuration is
distributed. Provider calls and remote-machine execution are not bundled.

Examples and fixtures must be synthetic or intentionally public. Keep private
documents, credentials, machine addresses, personal paths, generated outputs and
user-owned databases outside version control. File adapters read only inputs you
explicitly supply. Local JSON-lines commands communicate over standard input and
output; they do not open a network port.

Run the public-distribution regression check and the repository's normal suites
before publishing. A content scan reports its inspected scope; historical commits
and external copies retain their own lifecycle.

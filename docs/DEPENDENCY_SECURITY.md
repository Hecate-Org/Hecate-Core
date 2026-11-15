# Dependency security maintenance

The November 2026 refresh updates the locked HTTP, TLS trust, JWT, HTML selector,
image-processing, file-locking and development-tool packages. Python **3.11.5 or
newer** is required because fixed Soup Sieve releases no longer support earlier
3.11 patch versions. Python 3.11, 3.12 and 3.13 remain in the CI matrix.

`pyproject.toml` records minimum safe versions for direct dependencies and uv
constraints for affected transitive packages. Constraints do not install unused
extras. Use the committed lock for reproducible installations; uv constraints
are project settings and are not exported as wheel dependency metadata.

After changing dependencies, regenerate `uv.lock`, audit every locked registry
package version, run tests and rebuild the isolated service runtime from the
updated Runner production lock. Updating source checkouts alone does not update
services installed under `/opt/hecate`.

## Remaining upstream advisory

DiskCache 5.6.3 remains affected by unsafe pickle deserialization:
[GHSA-w8v5-vhqr-4h9v](https://github.com/advisories/GHSA-w8v5-vhqr-4h9v).
There is no patched release of the `diskcache` distribution in the package index.
Current pySigma 1.x requires it for ATT&CK/D3FEND caching. pySigma 2 uses the
separate `diskcache-community` distribution, but the current Kusto, CrowdStrike
and Elasticsearch backends require pySigma below 2. Forcing incompatible
dependencies would bypass those supported backend requirements.

The advisory remains visible and is not ignored. A full dependency audit will
continue to report it; PR checks reject new package/version/advisory matches.
Do not load cache databases supplied by other users or use an untrusted writable
cache directory. Dedicated service homes and restricted workspace permissions
limit who can write local state, but do not remove the vulnerable dependency.
Revisit removal when compatible upstream backends are available.

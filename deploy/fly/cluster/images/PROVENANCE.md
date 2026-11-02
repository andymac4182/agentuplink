# Cluster runtime distribution scope

The relay and authority retain the source/binary-bound Rust notice inventories
staged by scripts/container_notices.py. The separate rehearsal image stages
independent client and deadman inventories. The Redis image retains the exact
historical pinned Redis core notice bundle and its checksum verification.

The cluster relay, authority and Redis images add the distribution's Python 3
package for the bounded entrypoint; it is not in the historical image recipes.
The installed OS package versions are recorded alongside this file. Debian
copyright files and inherited OS notices are preserved. Package-version records
are provenance, not an assertion that all OS distribution notices are complete.
The inherited Redis externally built modules' exact binary/source linkage and
notice coverage remain unresolved; this wrapper does not select among Redis's
offered licenses or approve a distribution/compliance policy.

The immutable base digests and source-bound notice manifests do not alone pin
the additional OS repository package resolution. Record the actual resulting
image digest/package inventory, and verify extracted notices and executable
hashes before deploying. A new build/runtime acceptance is still required.

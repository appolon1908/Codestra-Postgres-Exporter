# Recovery and rollback design

PostgreSQL Exporter is stateless. Its recoverable authority is the signed configuration artifact, exact runtime image digest, monitoring-role SQL and secret reference names. PostgreSQL data backup is owned by the PostgreSQL authority and must never be copied by this exporter.

Before a runtime change, record the protected source SHA, exact image and config digests, deterministic checksum, private network identities, secret-file presence without values, monitoring-role grants and `pg_up`. Retain the previous pullable artifacts. An isolated restore consists of pulling and verifying those exact artifacts, rendering Compose without credentials, attaching only disposable PostgreSQL and private monitoring networks, installing an ephemeral least-privilege role, and proving `/metrics`, `pg_up == 1`, prohibited SQL denial and no host port.

Rollback requires an actually pullable previous image digest, verified configuration artifact digest and checksum. Reapply the previous configuration as a unit, verify the role is still compatible, and require private scrape recovery. If an upstream collector change is not backward compatible, use forward recovery. This document does not claim a production backup, restore or rollback rehearsal.

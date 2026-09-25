# Security policy

Report vulnerabilities privately through GitHub Security Advisories. Never put a database URI, password, certificate, customer row, production query output or other secret in an issue or pull request.

The exporter must remain private, non-root, read-only and capability-free. It receives only mounted secret-file references for a dedicated non-superuser monitoring role. Public DNS, public host-port publication, application-write privileges, database ownership, superuser, replication administration and bypass-RLS are forbidden.

Security changes require exact-head CI, normal review and promotion through the accepted branch lineage. Merging source does not create a database role, read a database or deploy the exporter.

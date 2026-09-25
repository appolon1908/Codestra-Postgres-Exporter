-- Review and run as an approved PostgreSQL administrator.
-- The password is intentionally absent. Install/rotate it through OpenBao or the
-- approved secret channel after this role is created.

DO $codestra$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname = 'codestra_postgres_exporter'
    ) THEN
        CREATE ROLE codestra_postgres_exporter
            LOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOINHERIT
            NOREPLICATION
            NOBYPASSRLS
            CONNECTION LIMIT 5;
    END IF;
END
$codestra$;

ALTER ROLE codestra_postgres_exporter
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOINHERIT
    NOREPLICATION
    NOBYPASSRLS
    CONNECTION LIMIT 5;

GRANT pg_monitor TO codestra_postgres_exporter;
ALTER ROLE codestra_postgres_exporter SET statement_timeout = '10s';
ALTER ROLE codestra_postgres_exporter SET lock_timeout = '2s';
ALTER ROLE codestra_postgres_exporter SET idle_in_transaction_session_timeout = '10s';

-- Grant CONNECT only to the approved monitoring database(s), for example:
-- GRANT CONNECT ON DATABASE postgres TO codestra_postgres_exporter;
-- Do not grant ownership, application-table writes, replication, schema-create,
-- function-execute beyond public defaults, or superuser privileges.

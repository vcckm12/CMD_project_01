#!/bin/sh
# Runs once on an empty data volume as the bootstrap superuser.
# Creates the migration owner (not used by the app) and the application database.
set -eu
psql -v ON_ERROR_STOP=1 -v owner_pw="$AG_OWNER_PASSWORD" -v dbname="$AG_DB_NAME" --username "$POSTGRES_USER" --dbname postgres <<'SQL'
CREATE ROLE ag_owner LOGIN CREATEROLE PASSWORD :'owner_pw';
CREATE DATABASE :"dbname" OWNER ag_owner ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE :"dbname" FROM PUBLIC;
SQL
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$AG_DB_NAME" <<'SQL'
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO ag_owner;
SQL

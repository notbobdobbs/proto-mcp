-- Record which door a tool call came through.
--
-- transport is "unix" for a socket peer and "http" for the loopback
-- door. caller_label is the configured name of an HTTP caller.
-- claimed_client is the name from MCP initialize; it is recorded
-- and never used to authorize. Unix rows leave it empty.
--
-- Existing rows are filled with empty strings. Those calls predate
-- the columns, and inventing a transport for them would be a guess.
-- New rows are filled by the audit writer.

-- +goose Up
ALTER TABLE audit_log ADD COLUMN transport TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_log ADD COLUMN caller_label TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_log ADD COLUMN claimed_client TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE audit_log DROP COLUMN claimed_client;
ALTER TABLE audit_log DROP COLUMN caller_label;
ALTER TABLE audit_log DROP COLUMN transport;

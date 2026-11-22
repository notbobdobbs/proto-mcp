-- Counts of remote read calls, and which local days have already
-- had their daily notification. A restart must not reset the day.

-- +goose Up
CREATE TABLE http_remote_reads (
    day TEXT PRIMARY KEY,
    n   INTEGER NOT NULL
);
CREATE TABLE http_notified (
    day TEXT PRIMARY KEY
);

-- +goose Down
DROP TABLE IF EXISTS http_notified;
DROP TABLE IF EXISTS http_remote_reads;

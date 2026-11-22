package httpmcp

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// readTools consume the daily remote read cap. mail_sync, drafts,
// sends, and mail_trash do not.
var readTools = map[string]struct{}{
	"account_whoami":           {},
	"mail_list":                {},
	"mail_search":              {},
	"mail_read":                {},
	"mail_read_thread":         {},
	"mail_list_attachments":    {},
	"mail_draft_list":          {},
	"labels_list":              {},
	"folders_list":             {},
	"calendar_list":            {},
	"calendar_events":          {},
	"calendar_read_event":      {},
	"mail_download_attachment": {},
}

// ReadCap is the per-local-day counter of remote reads. It lives in
// SQLite so a restart does not zero it. The Unix socket does not use it.
type ReadCap struct {
	db  *sql.DB
	now func() time.Time
	max func() int
}

func NewReadCap(db *sql.DB, now func() time.Time, max func() int) *ReadCap {
	if now == nil {
		now = time.Now
	}
	return &ReadCap{db: db, now: now, max: max}
}

// Take denies a read tool that would exceed the day's cap. Other
// tools are ignored. The Unix path must not call this.
func (r *ReadCap) Take(tool string) error {
	if r == nil || r.db == nil {
		return nil
	}
	if _, ok := readTools[tool]; !ok {
		return nil
	}
	max := 500
	if r.max != nil && r.max() > 0 {
		max = r.max()
	}
	day := r.now().In(time.Local).Format("2006-01-02")
	ctx := context.Background()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	err = tx.QueryRowContext(ctx, `SELECT n FROM http_remote_reads WHERE day = ?`, day).Scan(&n)
	if err == sql.ErrNoRows {
		n = 0
		err = nil
	}
	if err != nil {
		return err
	}
	if n >= max {
		return fmt.Errorf("remote read cap of %d per day reached", max)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO http_remote_reads (day, n) VALUES (?, 1)
ON CONFLICT(day) DO UPDATE SET n = n + 1`, day); err != nil {
		return err
	}
	return tx.Commit()
}

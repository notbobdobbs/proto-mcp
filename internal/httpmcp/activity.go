package httpmcp

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// ActivityText is the plain-text report of remote tool calls for
// today and the previous 7 local days. It never includes a body,
// subject, or recipient. Message ids are included only when ids is set.
func ActivityText(db *sql.DB, now time.Time, ids bool) (string, error) {
	loc := now.Location()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).AddDate(0, 0, -7)
	rows, err := db.QueryContext(context.Background(), `
SELECT tool, COALESCE(outcome, ''), COUNT(*)
FROM audit_log
WHERE transport = 'http' AND ts >= ? AND ts < ?
GROUP BY tool, outcome
ORDER BY tool, outcome`, start.Unix(), now.Add(24*time.Hour).Unix())
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var b strings.Builder
	fmt.Fprintf(&b, "remote calls since %s\n", start.Format("2006-01-02"))
	n := 0
	for rows.Next() {
		var tool, outcome string
		var count int
		if err := rows.Scan(&tool, &outcome, &count); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%s %s %d\n", tool, outcome, count)
		n += count
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	fmt.Fprintf(&b, "total %d\n", n)
	if !ids {
		return b.String(), nil
	}
	idRows, err := db.QueryContext(context.Background(), `
SELECT args_json FROM audit_log
WHERE transport = 'http' AND ts >= ? AND ts < ? AND args_json LIKE '%message_id%'`,
		start.Unix(), now.Add(24*time.Hour).Unix())
	if err != nil {
		return "", err
	}
	defer idRows.Close()
	b.WriteString("message ids:\n")
	for idRows.Next() {
		var args string
		if err := idRows.Scan(&args); err != nil {
			return "", err
		}
		if i := strings.Index(args, `"message_id":"`); i >= 0 {
			rest := args[i+len(`"message_id":"`):]
			if j := strings.IndexByte(rest, '"'); j >= 0 {
				fmt.Fprintf(&b, "%s\n", rest[:j])
			}
		}
	}
	return b.String(), idRows.Err()
}

// DailyNotice posts one notification for each completed local day in
// the last week that has remote calls and has not been posted yet.
// A day with no remote calls posts nothing. The text is counts only.
func DailyNotice(db *sql.DB, now time.Time, notify func(string) error) error {
	if notify == nil {
		return nil
	}
	loc := now.Location()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	for i := 1; i <= 7; i++ {
		day := today.AddDate(0, 0, -i)
		key := day.Format("2006-01-02")
		var already int
		err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM http_notified WHERE day = ?`, key).Scan(&already)
		if err != nil || already > 0 {
			continue
		}
		text, total, err := dayCounts(db, day)
		if err != nil {
			return err
		}
		if _, err := db.ExecContext(context.Background(), `INSERT INTO http_notified (day) VALUES (?)`, key); err != nil {
			return err
		}
		if total == 0 {
			continue
		}
		if err := notify(text); err != nil {
			return err
		}
	}
	return nil
}

func dayCounts(db *sql.DB, day time.Time) (string, int, error) {
	start := day.Unix()
	end := day.Add(24 * time.Hour).Unix()
	rows, err := db.QueryContext(context.Background(), `
SELECT tool, COALESCE(outcome, ''), COUNT(*)
FROM audit_log
WHERE transport = 'http' AND ts >= ? AND ts < ?
GROUP BY tool, outcome`, start, end)
	if err != nil {
		return "", 0, err
	}
	defer rows.Close()
	var total, reads, sends, denials int
	for rows.Next() {
		var tool, outcome string
		var n int
		if err := rows.Scan(&tool, &outcome, &n); err != nil {
			return "", 0, err
		}
		total += n
		if _, ok := readTools[tool]; ok {
			reads += n
		}
		if strings.HasPrefix(tool, "mail_send") || tool == "mail_reply" || tool == "mail_reply_all" || tool == "mail_forward" {
			sends += n
		}
		if outcome == "denied" {
			denials += n
		}
	}
	if err := rows.Err(); err != nil {
		return "", 0, err
	}
	return fmt.Sprintf("remote calls %s: total %d, reads %d, sends %d, denials %d", day.Format("2006-01-02"), total, reads, sends, denials), total, nil
}

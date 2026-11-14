package store

// markNoDump is hideFromDump. Tests replace it to record the paths
// the working copy asks to keep out of backups, including the WAL.
var markNoDump = hideFromDump

// hideWorkingFiles marks the plaintext database and its WAL. The WAL
// holds the same pages as the database until the next checkpoint, so
// a backup hint that covers only the main file misses the log.
func hideWorkingFiles(path string) {
	if path == "" || path == ":memory:" {
		return
	}
	markNoDump(path)
	markNoDump(path + "-wal")
}

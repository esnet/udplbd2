# Database Administration

udplbd uses **SQLite** as its state store. The design prioritizes correctness and recoverability: rows are never physically deleted during normal operation, migrations run automatically on startup, and an optional archive system provides a long-term audit trail.

## Schema design

The database uses an **append-only soft-delete** pattern. Every table that represents mutable state has a `deleted_at` column. When a reservation is freed or a token is revoked, the row is marked with the current timestamp rather than removed. The hot database retains these rows until the background cleanup task purges them.

This provides:

- **Crash safety:** the daemon can restart at any point and reconstruct its state from the database without data loss.
- **Historical inspection:** you can query which workers were assigned which slots at any past epoch, even after the reservation has ended.
- **Audit trail:** token creation, reservation lifecycle events, and session state changes are all preserved in time order.

On startup, udplbd also reconciles the `loadbalancer` table against `lb.instances` in the config file, adding, updating, or soft-deleting rows as needed to reflect any configuration changes.

## Migrations

Schema migrations are managed by `sqlx-migrate` and run **automatically on startup**, before any connections are accepted.

### Backup before migrate

When `database.backup_before_migrate: true` (the default), udplbd checks for pending migrations before running them. If any are found, it copies the database file to:

```
<original-filename>.pre-migrate.bak
```

For example: `/data/udplbd.db` → `/data/udplbd.db.pre-migrate.bak`. This file is overwritten on each upgrade that involves a migration — it always represents the state immediately before the most recent migration run. See [Installation — Upgrading](installation.md#upgrading) for how to restore from it.

## Cleanup

A background task runs every `database.cleanup_interval` (default `60s`) and permanently removes rows older than `database.cleanup_age` (default `4h`):

- **Soft-deleted rows** from the `sender`, `session`, `epoch`, `reservation`, `loadbalancer`, and `slot_demand` tables — those whose `deleted_at` is older than the threshold.
- **SmartNIC statistics** (`stat_global_sample`, `stat_lb_sample`, `stat_member_sample`) — rows whose `created_at` is older than the threshold.
- **Session state snapshots** — all but the 5 most-recent per active session.
- **Event number records** — all but the 5 most-recent per active reservation.

After each cleanup pass that removes rows, udplbd runs `VACUUM` to reclaim disk space and logs a per-table summary.

## Archive rotation

When `database.archive_dir` is set, rows that would be permanently deleted are instead copied into a rotating series of SQLite archive databases before being removed from the hot database. Each archive database has the same schema as the hot database.

Archive databases are named by their creation timestamp:

```
udplbd_archive_20260115120000.db
udplbd_archive_20260118120000.db
```

A new archive database is created when `database.archive_rotation` time has elapsed since the current archive was opened. When the total count of archive databases exceeds `database.archive_keep`, the oldest is deleted.

**Example configuration:**

```yaml
database:
  archive_dir: "/data/archive"
  archive_rotation: "72h"   # new archive file every 3 days
  archive_keep: 10          # keep the 10 most recent files (~30 days)
```

If `archive_dir` is not set, rows are discarded permanently when the cleanup task runs.

## Manual inspection

You can inspect the database from the host with `sqlite3`. Opening it read-only avoids interfering with the running container:

```sh
sqlite3 -readonly data/udplbd.db
```

Do not issue writes to the database while the container is running.

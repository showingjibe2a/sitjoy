## Database schema policy (IMPORTANT)

This repo **must never** create/alter/check database schema at runtime.

- Do **not** add any "ensure table/column", "auto-migrate", or `information_schema` probing logic in Python/JS.
- All schema changes must be delivered as explicit SQL migration files under `scripts/sql/*.sql`.


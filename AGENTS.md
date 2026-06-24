## Database schema policy (IMPORTANT)

This repo **must never** create/alter/check database schema at runtime.

- Do **not** add any "ensure table/column", "auto-migrate", or `information_schema` probing logic in Python/JS.
- All schema changes must be delivered as explicit SQL migration files under `scripts/sql/*.sql`.

## Shell / chrome UI (IMPORTANT)

- Do **not** let the global `button { border … }` unify rules in `style.css` apply to app-shell chrome (sidebar account button, drawer items, icon triggers, etc.). Add explicit `:not(.…)` exclusions or scoped resets in `app-shell.css`.
- Avoid gratuitous outline/box-shadow “wireframes” on dark shell surfaces; use opacity/background hover only unless accessibility requires a focus ring (then use subtle theme tokens, not bright white borders).


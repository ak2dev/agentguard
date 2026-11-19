# Supabase: Google and GitHub sign-in, and My scans

The site can let people sign in with Google or GitHub and keep the scan reports they choose to save. Supabase provides both the
sign-in (Supabase Auth) and the storage (one Postgres table under row-level security). The site stays static: the
browser talks to Supabase directly with the project's **publishable** key, and the database decides what each signed-in
user may read or write.

| Part | Where |
|---|---|
| Table, policies, limits | `supabase/migrations/20261118000000_saved_scans.sql` |
| Build-time switch and key check | `site/src/data/auth.ts` |
| Sign-in (OAuth with PKCE), session, saved-scan requests | `site/public/js/account.js` |
| Pages | `/signin/` (`site/src/pages/signin/`), `/account/` "My scans" (`site/src/pages/account/`), the Save button on `/scan/` |
| Test against a mocked Supabase | `site/tests/e2e/account.spec.mjs` |

With the URL and key unset, none of this is built: no sign-in link, no pages, no requests.

## What is stored

- `auth.users` (managed by Supabase): the name (or GitHub username) and email the provider shares, and sign-in times.
  Supabase links a Google and a GitHub sign-in with the same verified email to one user, so both see the same saved scans.
- `public.saved_scans`: one row per report a user saved with **Save to My scans**: label, verdict, score, finding
  count, rule pack and engine versions, and the report JSON (verdict, findings, evidence snippets). Never the scanned
  files. Rows are immutable, at most 200 per user, about 2 MB each, and deleted with the user.

Row-level security limits every read, insert and delete to `auth.uid() = user_id`. The `anon` role has no access. INSERT
is granted on the content columns only, so a client cannot choose a row's id, owner or timestamp.

## Set it up

1. **Create a Supabase project** (any plan) and note its URL, `https://<project-ref>.supabase.co`.
2. **Create the table.** Run the migration in Dashboard → SQL Editor, or with the CLI: `supabase link --project-ref
   <project-ref>` then `supabase db push`. Then confirm Dashboard → Advisors → Security Advisor shows no errors for
   `saved_scans`.
3. **Create a Google OAuth client.** In Google Cloud Console → APIs & Services:
   - OAuth consent screen: app name "Agent Guard", your support email, and the default scopes (`openid`, `email`,
     `profile`). Publish it when you are ready for anyone to sign in; while it is in testing, only listed test users can.
   - Credentials → Create credentials → OAuth client ID → **Web application**. Under **Authorized redirect URIs** add
     the callback URL shown on Supabase's Google provider page: `https://<project-ref>.supabase.co/auth/v1/callback`.
   - Copy the client ID and client secret.
4. **Turn on Google in Supabase.** Dashboard → Authentication → Sign In / Providers → Google: enable it and paste the
   client ID and secret. The secret stays in Supabase; it never goes in this repository or in Vercel.
   **GitHub** works the same way: on GitHub, Settings → Developer settings → OAuth Apps → **New OAuth App**, with
   Homepage URL `https://agentguard-ak2dev.vercel.app` and Authorization callback URL
   `https://<project-ref>.supabase.co/auth/v1/callback`. Generate a client secret, then paste the client ID and secret
   into Dashboard → Authentication → Sign In / Providers → GitHub and enable it. The site's button for a provider works
   only once that provider is enabled here.
5. **Allow the site's return address.** Dashboard → Authentication → URL Configuration:
   - Site URL: `https://agentguard-ak2dev.vercel.app`
   - Redirect URLs: `https://agentguard-ak2dev.vercel.app/account/`, and for local testing `http://127.0.0.1:4321/account/`
     and `http://localhost:4321/account/`. Add a pattern for Vercel preview deployments only if you want sign-in there.
6. **Give the site the public values.** Dashboard → Project Settings → API Keys: copy the **publishable** key
   (`sb_publishable_…`; the legacy `anon` key also works). Never use a secret or `service_role` key: the build stops if
   you do, because those keys bypass row-level security.
   - Vercel: Project → Settings → Environment Variables, for Production (and Preview if wanted):
     `PUBLIC_SUPABASE_URL` and `PUBLIC_SUPABASE_PUBLISHABLE_KEY`. `SUPABASE_URL` and `SUPABASE_KEY` work too. Redeploy:
     the values are read when the site is built.
   - Local: copy `site/.env.example` to `site/.env` and fill it in (`.env` is git-ignored).

## Content Security Policy

`vercel.json` allows `https://*.supabase.co` in `connect-src`. Each page's own CSP (`site/src/layouts/Base.astro`)
narrows that to the one project the site was built with, so the browser enforces the exact origin. If you move Supabase
Auth to a custom domain, add that origin to `vercel.json`.

## Check it

```bash
cd site
PUBLIC_FEATURE_SCAN=1 PUBLIC_SUPABASE_URL=https://example-ref.supabase.co PUBLIC_SUPABASE_PUBLISHABLE_KEY=sb_publishable_test npm run build
npx playwright test tests/e2e/account.spec.mjs   # mocked Supabase: nothing reaches a real project
```

Then, with the real values, sign in on the deployed site, scan something, save it, and open it from My scans.

-- Agent Guard: scan reports that signed-in users chose to save ("My scans").
--
-- The site talks to this table from the browser with the project's publishable
-- key and the user's own access token, so row-level security is what keeps one
-- user's reports from another. Every policy is scoped to auth.uid(); the anon
-- role gets nothing. Reports are immutable once saved: there is no UPDATE.
--
-- Run it once: Supabase dashboard > SQL Editor, or `supabase db push`.

create table if not exists public.saved_scans (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null default auth.uid() references auth.users (id) on delete cascade,
  created_at    timestamptz not null default now(),
  -- what was scanned, as the scan page labelled it (a link, "Pasted text", "3 dropped file(s)")
  label         text not null check (char_length(label) between 1 and 2048),
  verdict       text not null check (verdict in ('ALLOW', 'REVIEW', 'BLOCK')),
  score         integer check (score between 0 and 100),
  finding_count integer not null default 0 check (finding_count >= 0),
  rule_pack     text check (char_length(rule_pack) <= 64),
  engine        text check (char_length(engine) <= 64),
  -- 'device': scanned in the browser; 'server': an Agent Guard Web report (server_key is its permalink key)
  source        text not null default 'device' check (source in ('device', 'server')),
  server_key    text check (server_key ~ '^[0-9a-f]{32}$'),
  -- the findings JSON exactly as the scan page rendered it (never the scanned files)
  report        jsonb not null check (jsonb_typeof(report) = 'object' and pg_column_size(report) <= 2000000)
);

create index if not exists saved_scans_user_created on public.saved_scans (user_id, created_at desc);

alter table public.saved_scans enable row level security;

drop policy if exists "Users read their own saved scans" on public.saved_scans;
create policy "Users read their own saved scans" on public.saved_scans
  for select to authenticated using ((select auth.uid()) = user_id);

drop policy if exists "Users save scans as themselves" on public.saved_scans;
create policy "Users save scans as themselves" on public.saved_scans
  for insert to authenticated with check ((select auth.uid()) = user_id);

drop policy if exists "Users delete their own saved scans" on public.saved_scans;
create policy "Users delete their own saved scans" on public.saved_scans
  for delete to authenticated using ((select auth.uid()) = user_id);

-- Supabase's default privileges grant everything on new public tables to anon and
-- authenticated. Take that back, then grant only what the site uses. INSERT is limited
-- to the content columns, so a client cannot choose its own id, owner or timestamp.
revoke all on table public.saved_scans from anon, authenticated;
grant select, delete on table public.saved_scans to authenticated;
grant insert (label, verdict, score, finding_count, rule_pack, engine, source, server_key, report)
  on table public.saved_scans to authenticated;

-- A cap per user keeps one account from filling the project's storage.
create or replace function public.saved_scans_limit()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if (select count(*) from public.saved_scans where user_id = new.user_id) >= 200 then
    raise exception 'You can keep at most 200 saved scans. Delete some to save more.'
      using errcode = 'check_violation';
  end if;
  return new;
end;
$$;

revoke all on function public.saved_scans_limit() from public, anon, authenticated;

drop trigger if exists saved_scans_limit on public.saved_scans;
create trigger saved_scans_limit
  before insert on public.saved_scans
  for each row execute function public.saved_scans_limit();

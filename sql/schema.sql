-- ---------------------------------------------------------------------------
-- PROJET 5 — CYBER IOC ENRICHER
-- Script à coller dans Supabase > SQL Editor > New query, puis « Run ».
-- Il crée la table qui stocke chaque analyse d'IOC.
-- ---------------------------------------------------------------------------

create table if not exists public.ioc_analyses (
  id          bigint generated always as identity primary key,
  ioc         text        not null,
  ioc_type    text        not null check (ioc_type in ('ip', 'domain', 'hash')),
  risk_level  text        not null check (risk_level in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  risk_score  integer     not null check (risk_score between 0 and 100),
  source_api  text,
  summary     jsonb       not null default '{}'::jsonb,
  reasons     jsonb       not null default '[]'::jsonb,
  created_at  timestamptz not null default now()
);

-- Index utile pour l'historique (tri par date) et la recherche par IOC.
create index if not exists ioc_analyses_created_at_idx on public.ioc_analyses (created_at desc);
create index if not exists ioc_analyses_ioc_idx        on public.ioc_analyses (ioc);

-- ---------------------------------------------------------------------------
-- Sécurité : la clé « anon » est publique, on limite donc ce qu'elle peut faire.
-- L'application (rôle anon) doit pouvoir lire, insérer et supprimer ses analyses.
-- ---------------------------------------------------------------------------
alter table public.ioc_analyses enable row level security;

drop policy if exists "ioc_select_anon" on public.ioc_analyses;
create policy "ioc_select_anon"
  on public.ioc_analyses for select
  to anon, authenticated
  using (true);

drop policy if exists "ioc_insert_anon" on public.ioc_analyses;
create policy "ioc_insert_anon"
  on public.ioc_analyses for insert
  to anon, authenticated
  with check (true);

drop policy if exists "ioc_delete_anon" on public.ioc_analyses;
create policy "ioc_delete_anon"
  on public.ioc_analyses for delete
  to anon, authenticated
  using (true);

-- ---------------------------------------------------------------------------
-- Vérification : la table doit apparaître dans Table Editor.
-- ---------------------------------------------------------------------------
select 'table ioc_analyses prete' as resultat;

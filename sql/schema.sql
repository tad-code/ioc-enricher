-- ---------------------------------------------------------------------------
-- ENRICHISSEMENT D'IOC — schéma de la base
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
-- SÉCURITÉ — à lire avant d'exécuter
--
-- Mode recommandé (celui utilisé en production) : l'application parle à la base
-- avec une clé SECRÈTE, côté serveur uniquement. Les règles RLS restent donc
-- fermées au rôle « anon » : même si quelqu'un connaît l'URL du projet ou la
-- clé publique, il ne peut ni lire, ni insérer, ni supprimer la moindre ligne.
--
-- Le bloc « mode dégradé » en fin de fichier n'est à décommenter que si vous
-- utilisez la clé publique (anon) sans clé secrète.
-- ---------------------------------------------------------------------------
alter table public.ioc_analyses enable row level security;

drop policy if exists "ioc_select_anon" on public.ioc_analyses;
drop policy if exists "ioc_insert_anon" on public.ioc_analyses;
drop policy if exists "ioc_delete_anon" on public.ioc_analyses;

-- ---------------------------------------------------------------------------
-- Vérification : la table doit apparaître dans Table Editor, et l'API REST
-- doit répondre 401/403 (et non des données) avec la clé publique.
-- ---------------------------------------------------------------------------
select 'table ioc_analyses prete et fermee aux acces publics' as resultat;

-- ---------------------------------------------------------------------------
-- MODE DÉGRADÉ (projet d'apprentissage sans clé secrète)
-- Décommentez les 3 politiques ci-dessous uniquement si SUPABASE_SECRET_KEY
-- n'est pas définie. Elles ouvrent la table EN ÉCRITURE ET SUPPRESSION à
-- quiconque possède la clé publique : à éviter en dehors d'un exercice.
-- ---------------------------------------------------------------------------
-- create policy "ioc_select_anon" on public.ioc_analyses
--   for select to anon, authenticated using (true);
-- create policy "ioc_insert_anon" on public.ioc_analyses
--   for insert to anon, authenticated with check (true);
-- create policy "ioc_delete_anon" on public.ioc_analyses
--   for delete to anon, authenticated using (true);

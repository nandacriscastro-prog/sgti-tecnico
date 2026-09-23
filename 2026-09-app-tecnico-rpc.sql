-- =====================================================================
-- App dos Técnicos (sgti-tecnico) — conclusão de OS pelo celular
-- Rodar UMA vez no Supabase: SQL Editor → New query → colar tudo → Run
-- =====================================================================
-- Por quê: desde a migração para Supabase Auth + RLS (set/2026), a tabela
-- ordens_servico só aceita escrita de usuário logado. O app dos técnicos
-- entra só com nome + PIN (sem login Supabase), então o PATCH dele era
-- recusado em silêncio (HTTP 200, zero linhas alteradas) e o app dizia
-- "OS enviada com sucesso" sem ter salvo nada.
--
-- Solução: o app não escreve mais direto na tabela. Ele chama duas funções
-- que conferem o PIN no banco e só permitem UMA ação: concluir uma OS
-- aberta do contrato 181/2026 com o relatório de campo. A tabela continua
-- travada para escrita anônima.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- 1) Técnicos habilitados no app e seus PINs (guardados como hash, nunca em texto)
create table if not exists public.tecnicos_app (
  nome      text primary key,
  pin_hash  text not null,
  ativo     boolean not null default true,
  criado_em timestamptz not null default now()
);
alter table public.tecnicos_app enable row level security;
-- Sem nenhuma policy: ninguém lê nem altera essa tabela pela API.
-- Só as funções abaixo (security definer) conseguem consultar.

-- PIN inicial 1234 para os técnicos que já estavam no app.
-- Troque para PINs individuais assim que possível (ver final do arquivo).
insert into public.tecnicos_app (nome, pin_hash) values
  ('Flávio Fonseca de Souza',        extensions.crypt('1234', extensions.gen_salt('bf'))),
  ('George Lúcio Souza Vieira',      extensions.crypt('1234', extensions.gen_salt('bf'))),
  ('Glecion Louzada da Silva',       extensions.crypt('1234', extensions.gen_salt('bf'))),
  ('Joelmir Júlio Barbosa',          extensions.crypt('1234', extensions.gen_salt('bf'))),
  ('Marvin Roger da Silva Inocente', extensions.crypt('1234', extensions.gen_salt('bf'))),
  ('Renivaldo da Silva Prado',       extensions.crypt('1234', extensions.gen_salt('bf'))),
  ('Roger Daltrey Augusto',          extensions.crypt('1234', extensions.gen_salt('bf'))),
  ('Rogério Souza Gomes',            extensions.crypt('1234', extensions.gen_salt('bf'))),
  ('Wesley Roger Vesiane Lopes',     extensions.crypt('1234', extensions.gen_salt('bf')))
on conflict (nome) do nothing;

-- 2) Conferir nome + PIN (usado na tela de login do app)
create or replace function public.tecnico_login(p_nome text, p_pin text)
returns boolean
language sql
stable
security definer
set search_path = public, extensions
as $$
  select exists (
    select 1 from public.tecnicos_app
    where nome = p_nome and ativo
      and pin_hash = extensions.crypt(p_pin, pin_hash)
  );
$$;

-- 3) Concluir uma OS pelo app
--    Só aceita: PIN válido, OS do contrato 181/2026, presencial (não remoto),
--    com status Aberta / Em andamento / Reaberta. Nada além de retorno_campo,
--    status e data_conclusao é alterado. avaliacao fica em branco para o fiscal.
create or replace function public.tecnico_concluir_os(
  p_nome text,
  p_pin text,
  p_numero text,
  p_retorno text,
  p_data_conclusao date
)
returns json
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_os record;
begin
  if not public.tecnico_login(p_nome, p_pin) then
    raise exception 'PIN_INVALIDO: nome ou PIN não conferem';
  end if;

  select id, status, contrato, tipo into v_os
    from public.ordens_servico
   where numero = p_numero
   for update;

  if not found then
    raise exception 'OS_NAO_ENCONTRADA: OS % não existe no sistema', p_numero;
  end if;

  if coalesce(v_os.contrato, '') <> '181/2026' then
    raise exception 'OS_CONTRATO: OS % não é do contrato 181/2026', p_numero;
  end if;

  if v_os.tipo = 'Atendimento Remoto' then
    raise exception 'OS_REMOTA: OS % é de atendimento remoto', p_numero;
  end if;

  if v_os.status = 'Concluída' then
    -- Já concluída (pelo fiscal ou por um envio anterior). Não sobrescreve nada.
    return json_build_object('ok', false, 'motivo', 'ja_concluida');
  end if;

  if coalesce(v_os.status, 'Aberta') not in ('Aberta', 'Em andamento', 'Reaberta') then
    raise exception 'OS_STATUS: OS % está com status "%" e não pode ser concluída pelo app', p_numero, v_os.status;
  end if;

  -- Garante que o relatório é JSON válido antes de gravar
  perform p_retorno::json;

  update public.ordens_servico
     set retorno_campo  = p_retorno,
         status         = 'Concluída',
         data_conclusao = p_data_conclusao
   where id = v_os.id;

  return json_build_object('ok', true);
end;
$$;

revoke all on function public.tecnico_login(text, text) from public;
revoke all on function public.tecnico_concluir_os(text, text, text, text, date) from public;
grant execute on function public.tecnico_login(text, text) to anon, authenticated;
grant execute on function public.tecnico_concluir_os(text, text, text, text, date) to anon, authenticated;

-- Faz a API enxergar as funções novas na hora
notify pgrst, 'reload schema';

-- =====================================================================
-- MANUTENÇÃO (não precisa rodar agora — use quando precisar)
-- =====================================================================
-- Trocar o PIN de um técnico:
--   update public.tecnicos_app
--      set pin_hash = extensions.crypt('4821', extensions.gen_salt('bf'))
--    where nome = 'Flávio Fonseca de Souza';
--
-- Incluir técnico novo (o nome tem que ser IGUAL ao da lista do app):
--   insert into public.tecnicos_app (nome, pin_hash)
--   values ('Nome Completo', extensions.crypt('1234', extensions.gen_salt('bf')));
--
-- Bloquear acesso de quem saiu da empresa:
--   update public.tecnicos_app set ativo = false where nome = 'Nome Completo';

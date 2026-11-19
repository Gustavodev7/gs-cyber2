-- Esquema do banco (PostgreSQL). So dados sinteticos (LGPD, RT-19).
-- Privilegio minimo (RT-08):
--   painel_ro  so le VIEWS e executa FUNCOES SECURITY DEFINER especificas.
--              NAO le nenhuma tabela: nem operador (hashes, segredos TOTP), nem
--              titular_acesso. Mesmo com uma falha no app, a tabela de usuarios
--              (o que o atacante extraiu no INC-VA-0712) nao pode ser lida.
--   ingest_w   INSERT na telemetria (+ SELECT, exigido pelo ON CONFLICT do ingest).
--   vila_owner dono do schema; usado so na carga inicial (seed), fora do app.
-- Os usuarios painel_ro e ingest_w sao criados em initdb/05-roles.sh com as
-- senhas do .env.

CREATE SCHEMA IF NOT EXISTS vila;
ALTER ROLE vila_owner SET search_path = vila, public;
ALTER ROLE painel_ro  SET search_path = vila;
ALTER ROLE ingest_w   SET search_path = vila;
SET search_path TO vila, public;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Operadores do painel. Senha: PBKDF2-SHA256 (200 mil iteracoes) + salt aleatorio
-- por usuario; segredo TOTP para o MFA (RT-09).
CREATE TABLE IF NOT EXISTS operador (
    login        TEXT PRIMARY KEY CHECK (login ~ '^[a-z0-9-]{1,40}$'),
    perfil       TEXT NOT NULL CHECK (perfil IN ('operador','tecnico','coordenacao','auditor')),
    senha_hash   TEXT NOT NULL,
    salt         TEXT NOT NULL,
    totp_secret  TEXT NOT NULL
);

-- Pessoas com credencial de acesso fisico (cracha). Pseudonimizadas: so apelido
-- sintetico e hash do cracha, nunca nome/CPF (RT-19, minimizacao).
CREATE TABLE IF NOT EXISTS titular_acesso (
    id           SERIAL PRIMARY KEY,
    apelido      TEXT NOT NULL,
    cracha_hash  TEXT NOT NULL,
    papel        TEXT NOT NULL
);

-- Historico de eventos de acesso/telemetria (base do campo de busca do painel).
-- Retencao: 90 dias (ver RIPD); a coluna do titular e o hash, nunca a pessoa.
CREATE TABLE IF NOT EXISTS historico_acesso (
    ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
    espaco       TEXT NOT NULL,
    recurso      TEXT NOT NULL,
    dispositivo  TEXT NOT NULL,
    evento       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_hist_disp ON historico_acesso (dispositivo);
CREATE INDEX IF NOT EXISTS ix_hist_ts   ON historico_acesso (ts);

-- Telemetria consolidada que chega dos nos de borda (store-and-forward).
-- event_id unico: reenvio na reconciliacao nao duplica.
CREATE TABLE IF NOT EXISTS telemetria (
    event_id     UUID PRIMARY KEY,
    borda        TEXT NOT NULL,
    dispositivo  TEXT NOT NULL,
    espaco       TEXT NOT NULL,
    recurso      TEXT NOT NULL,
    valor        DOUBLE PRECISION NOT NULL,
    ts_origem    TIMESTAMPTZ NOT NULL,
    recebido_em  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_tel_disp_ts ON telemetria (dispositivo, ts_origem DESC);

-- Comandos de atuador pedidos pelo painel. Alto impacto fica aguardando
-- aprovacao de OUTRA pessoa da coordenacao (quatro olhos, RT-15).
CREATE TABLE IF NOT EXISTS comando_atuador (
    id           BIGSERIAL PRIMARY KEY,
    solicitado_em TIMESTAMPTZ NOT NULL DEFAULT now(),
    solicitante  TEXT NOT NULL REFERENCES operador(login),
    perfil       TEXT NOT NULL,
    acao         TEXT NOT NULL,
    alvo         TEXT NOT NULL,
    risco        TEXT NOT NULL CHECK (risco IN ('baixo','alto')),
    status       TEXT NOT NULL CHECK (status IN ('executado','aguardando_aprovacao','aprovado','negado')),
    aprovador    TEXT REFERENCES operador(login),
    decidido_em  TIMESTAMPTZ
);

-- Agendamento das bombas (o que o atacante alterou no INC-VA-0712). So o owner
-- escreve; no sistema novo a mudanca passa por registrar_comando + aprovacao.
CREATE TABLE IF NOT EXISTS agendamento_bomba (
    bomba         TEXT PRIMARY KEY,
    horario       TIME NOT NULL,
    atualizado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO agendamento_bomba(bomba, horario) VALUES
  ('escola-bomba', '06:00'), ('abrigo-bomba', '07:00')
ON CONFLICT (bomba) DO NOTHING;

-- ------------------------------------------------------------------ views
CREATE OR REPLACE VIEW v_historico_acesso AS
  SELECT ts, espaco, recurso, dispositivo, evento FROM historico_acesso;

CREATE OR REPLACE VIEW v_telemetria_recente AS
  SELECT DISTINCT ON (dispositivo) dispositivo, espaco, recurso, valor, ts_origem
  FROM telemetria ORDER BY dispositivo, ts_origem DESC;

CREATE OR REPLACE VIEW v_comando_atuador AS
  SELECT id, solicitado_em, solicitante, perfil, acao, alvo, risco, status, aprovador, decidido_em
  FROM comando_atuador;

-- ---------------------------------------------------- funcoes de autenticacao
-- O app nunca le a tabela operador. Primeiro pega o salt (que nao e segredo),
-- calcula o PBKDF2 e pede ao banco para conferir. So com a senha certa o banco
-- devolve o perfil e o segredo TOTP daquele usuario.
CREATE OR REPLACE FUNCTION salt_operador(p_login TEXT) RETURNS TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = vila, pg_temp AS $$
  SELECT salt FROM operador WHERE login = p_login;
$$;

CREATE OR REPLACE FUNCTION autenticar(p_login TEXT, p_hash TEXT)
RETURNS TABLE (perfil TEXT, totp_secret TEXT)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = vila, pg_temp AS $$
  SELECT o.perfil, o.totp_secret FROM operador o
  WHERE o.login = p_login AND o.senha_hash = p_hash;
$$;

-- -------------------------------------------------- funcoes de atuador (RBAC)
-- A politica tambem vale no banco (defesa em profundidade): o perfil vem da
-- tabela, nao do app.
CREATE OR REPLACE FUNCTION registrar_comando(p_login TEXT, p_acao TEXT, p_alvo TEXT)
RETURNS TABLE (id BIGINT, risco TEXT, status TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = vila, pg_temp AS $$
DECLARE
  v_perfil TEXT;
  v_risco  TEXT;
  v_status TEXT;
BEGIN
  SELECT o.perfil INTO v_perfil FROM operador o WHERE o.login = p_login;
  IF v_perfil IS NULL THEN RAISE EXCEPTION 'operador desconhecido'; END IF;
  v_risco := CASE
    WHEN p_acao IN ('atuador_modo_seguro','bomba_modo_economia','isolar_dispositivo') THEN 'baixo'
    WHEN p_acao IN ('desligar_bomba','liberar_todas_portas','agendamento_bomba') THEN 'alto'
    ELSE NULL END;
  IF v_risco IS NULL THEN RAISE EXCEPTION 'acao desconhecida'; END IF;
  IF v_risco = 'baixo' AND v_perfil NOT IN ('tecnico','coordenacao') THEN
    RAISE EXCEPTION 'perfil sem permissao';
  END IF;
  IF v_risco = 'alto' AND v_perfil <> 'coordenacao' THEN
    RAISE EXCEPTION 'perfil sem permissao';
  END IF;
  v_status := CASE WHEN v_risco = 'baixo' THEN 'executado' ELSE 'aguardando_aprovacao' END;
  RETURN QUERY
    INSERT INTO comando_atuador(solicitante, perfil, acao, alvo, risco, status)
    VALUES (p_login, v_perfil, p_acao, p_alvo, v_risco, v_status)
    RETURNING comando_atuador.id, comando_atuador.risco, comando_atuador.status;
END $$;

CREATE OR REPLACE FUNCTION decidir_comando(p_id BIGINT, p_aprovador TEXT, p_aprovar BOOLEAN)
RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = vila, pg_temp AS $$
DECLARE
  c comando_atuador%ROWTYPE;
  v_perfil TEXT;
BEGIN
  SELECT o.perfil INTO v_perfil FROM operador o WHERE o.login = p_aprovador;
  IF v_perfil IS DISTINCT FROM 'coordenacao' THEN RAISE EXCEPTION 'perfil sem permissao'; END IF;
  SELECT * INTO c FROM comando_atuador WHERE comando_atuador.id = p_id FOR UPDATE;
  IF NOT FOUND OR c.status <> 'aguardando_aprovacao' THEN RAISE EXCEPTION 'comando nao pendente'; END IF;
  IF c.solicitante = p_aprovador THEN RAISE EXCEPTION 'aprovador deve ser outra pessoa'; END IF;
  UPDATE comando_atuador
     SET status = CASE WHEN p_aprovar THEN 'aprovado' ELSE 'negado' END,
         aprovador = p_aprovador, decidido_em = now()
   WHERE comando_atuador.id = p_id;
  RETURN CASE WHEN p_aprovar THEN 'aprovado' ELSE 'negado' END;
END $$;

-- ------------------------------------------------------------------ grants
-- Funcoes nascem executaveis por PUBLIC: revogar e conceder so a quem precisa.
REVOKE ALL ON ALL TABLES IN SCHEMA vila FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA vila FROM PUBLIC;

GRANT USAGE ON SCHEMA vila TO painel_ro, ingest_w;
GRANT SELECT ON v_historico_acesso, v_telemetria_recente, v_comando_atuador TO painel_ro;
GRANT EXECUTE ON FUNCTION salt_operador(TEXT), autenticar(TEXT, TEXT),
  registrar_comando(TEXT, TEXT, TEXT), decidir_comando(BIGINT, TEXT, BOOLEAN) TO painel_ro;
-- painel_ro NAO recebe nada em operador, titular_acesso, comando_atuador nem telemetria.

-- INSERT grava a telemetria; SELECT e exigido pelo ON CONFLICT (event_id) do
-- ingest (arbitro do indice), que deduplica reenvios do store-and-forward.
GRANT INSERT, SELECT ON telemetria TO ingest_w;

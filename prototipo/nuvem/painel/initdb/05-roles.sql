-- Cria os usuarios de aplicacao com as senhas do .env (nunca fixas no codigo).
-- Roda uma vez, na criacao do banco (docker-entrypoint-initdb.d, antes do schema).
-- Em .sql (nao .sh) para nao depender de bit de execucao: o bind mount do Docker
-- Desktop no macOS costuma vir como noexec e quebra scripts .sh.
-- \getenv le o ambiente do psql no container (compose define as duas senhas no
-- servico postgres). log_statement=none: a senha nao vai para o log do banco.
\getenv pw_ro PAINEL_RO_PASSWORD
\getenv pw_ing INGEST_PASSWORD
SET log_statement = 'none';
CREATE ROLE painel_ro LOGIN PASSWORD :'pw_ro';
CREATE ROLE ingest_w  LOGIN PASSWORD :'pw_ing';

"""
Popula o banco com dados 100% sinteticos (RT-19). Nenhum dado real.
Gera operadores com MFA, titulares pseudonimizados e historico de acesso.

Senhas: geradas na hora (aleatorias) e mostradas UMA vez no terminal, junto com
o segredo TOTP, para o laboratorio. Nada de senha fixa no repositorio.
Uso (dentro da rede do compose, ver scripts/subir_lab.sh):
  PAINEL_DB_DSN_OWNER=postgresql://vila_owner:...@postgres:5432/vila python seed_sintetico.py
Saida: credenciais_lab.txt (NAO versionado) com login, perfil, senha e TOTP.
"""

import hashlib
import os
import random
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pyotp

random.seed(712)  # historico reproduzivel
ESPACOS = ["centro", "escola", "ubs", "horta", "abrigo"]
RECURSOS = ["energia", "agua", "acesso", "ambiente"]
OPERADORES = [
    # login sintetico, perfil (RBAC RT-09)
    ("ana", "coordenacao"),
    ("beto", "coordenacao"),  # segunda pessoa da coordenacao: aprova o que "ana" pede
    ("bruno", "operador"),
    ("clara", "tecnico"),
    ("davi", "auditor"),
]
SAIDA = Path(os.environ.get("CREDENCIAIS_SAIDA", "credenciais_lab.txt"))


def senha_hash(p, salt):
    return hashlib.pbkdf2_hmac("sha256", p.encode(), salt.encode(), 200_000).hex()


def main():
    dsn = os.environ["PAINEL_DB_DSN_OWNER"]
    linhas = ["login perfil senha totp_secret  (SO laboratorio; nao versionar)"]
    with psycopg.connect(dsn) as con, con.cursor() as cur:
        cur.execute("SET search_path TO vila, public")
        for login, perfil in OPERADORES:
            salt = secrets.token_hex(16)  # salt aleatorio por usuario
            senha = secrets.token_urlsafe(12)
            totp = pyotp.random_base32()
            cur.execute(
                "INSERT INTO operador(login,perfil,senha_hash,salt,totp_secret) "
                "VALUES(%s,%s,%s,%s,%s) ON CONFLICT (login) DO UPDATE SET "
                "senha_hash=EXCLUDED.senha_hash, salt=EXCLUDED.salt, "
                "totp_secret=EXCLUDED.totp_secret, perfil=EXCLUDED.perfil",
                (login, perfil, senha_hash(senha, salt), salt, totp),
            )
            linhas.append(f"{login} {perfil} {senha} {totp}")

        cur.execute("SELECT count(*) FROM titular_acesso")
        if cur.fetchone()[0] == 0:
            for i in range(40):
                cur.execute(
                    "INSERT INTO titular_acesso(apelido,cracha_hash,papel) VALUES(%s,%s,%s)",
                    (
                        f"voluntario-{i:02d}",
                        hashlib.sha256(f"cracha-sintetico-{i}".encode()).hexdigest(),
                        random.choice(["voluntario", "tecnico", "equipe-ubs"]),
                    ),
                )
            base = datetime.now(UTC) - timedelta(days=7)
            eventos = [
                "leitura-ok",
                "acesso-liberado",
                "acesso-negado",
                "nivel-baixo",
                "temp-fora-faixa",
                "porta-aberta",
                "bomba-ligada",
                "bomba-desligada",
            ]
            for n in range(2000):
                cur.execute(
                    "INSERT INTO historico_acesso(ts,espaco,recurso,dispositivo,evento) "
                    "VALUES(%s,%s,%s,%s,%s)",
                    (
                        base + timedelta(minutes=n * 5 + random.randint(0, 4)),
                        random.choice(ESPACOS),
                        random.choice(RECURSOS),
                        f"{random.choice(ESPACOS)}-sensor-{random.randint(1, 5)}",
                        random.choice(eventos),
                    ),
                )
        con.commit()
    SAIDA.write_text("\n".join(linhas) + "\n", encoding="utf-8")
    os.chmod(SAIDA, 0o600)
    print("\n".join(linhas))
    print(
        f"\nseed sintetico concluido: {len(OPERADORES)} operadores (credenciais em {SAIDA})."
    )
    print(
        "Cadastre cada totp_secret num app autenticador (ou use: python -c "
        "\"import pyotp;print(pyotp.TOTP('SEGREDO').now())\")."
    )


if __name__ == "__main__":
    main()

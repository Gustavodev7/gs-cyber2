FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3 "psycopg[binary]==3.2.3" gunicorn==23.0.0
COPY app.py gunicorn_conf.py ./
# root so para ler a chave privada montada (modo 400). Nenhuma porta publicada no
# host: so a borda alcanca este servico, pela rede "wan".
CMD ["gunicorn", "-c", "gunicorn_conf.py", "app:app"]

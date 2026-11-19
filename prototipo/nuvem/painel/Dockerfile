FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app_corrigido.py seed_sintetico.py ./
COPY templates ./templates
COPY static ./static
# roda com usuario sem privilegio
RUN useradd -m -u 10001 painel
USER painel
EXPOSE 8080
# 0.0.0.0 dentro do container; quem restringe ao loopback e a publicacao da
# porta no compose (e o WAF na frente).
CMD ["gunicorn", "-b", "0.0.0.0:8080", "-w", "2", "app_corrigido:app"]

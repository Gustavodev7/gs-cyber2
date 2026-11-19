FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir paho-mqtt==2.1.0 requests==2.32.3
COPY no_borda.py .
# Roda como root dentro do container so para ler a chave privada montada (modo
# 400). O container so enxerga as redes "iot" e "wan" e o proprio par de chaves.
CMD ["python", "no_borda.py"]

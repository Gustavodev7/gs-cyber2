FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir paho-mqtt==2.1.0
COPY sensor.py .
# Roda como root dentro do container so para ler a chave privada montada (modo
# 400, dono = usuario do host). O container nao publica porta e so enxerga a
# rede "iot" e o proprio par de chaves.
CMD ["python", "sensor.py"]

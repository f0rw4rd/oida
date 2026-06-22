FROM python:3.11-slim

WORKDIR /app

COPY ads_server.py /app/

EXPOSE 48898

CMD ["python3", "ads_server.py"]

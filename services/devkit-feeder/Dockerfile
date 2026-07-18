# DX2-live one-shot feeder: injects an SSH brute-force burst into raw.events so a
# fresh `docker compose up` yields a REAL alert with no manual step.
FROM python:3.14-slim
RUN pip install --no-cache-dir redis==5.0.8
WORKDIR /app
COPY services/devkit-feeder/feed.py /app/feed.py
CMD ["python", "feed.py"]

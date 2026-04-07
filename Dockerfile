FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY . /app

ENV ENABLE_WEB_INTERFACE=true

CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000"]

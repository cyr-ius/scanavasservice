FROM python:3.12-slim

ARG VERSION=1.0.0
ENV VERSION=${VERSION}

ENV PYTHONUNBUFFERED=1

RUN apt-get update
RUN apt-get install -y build-essential curl netcat-openbsd pkg-config libssl-dev ca-certificates
RUN rm -rf /var/lib/apt/lists/*

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

RUN chmod +x entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["bash", "entrypoint.sh"]

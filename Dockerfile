FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV HOME=/tmp/semgrep-home
ENV SEMGREP_SETTINGS_FILE=/tmp/semgrep-home/settings.yml
ENV SEMGREP_SEND_METRICS=off
ENV SEMGREP_ENABLE_VERSION_CHECK=0

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /tmp/semgrep-home \
    && printf 'has_shown_metrics_notification: true\nanonymous_user_id: 00000000-0000-0000-0000-000000000000\n' > /tmp/semgrep-home/settings.yml

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

COPY . .

CMD ["python", "--version"]

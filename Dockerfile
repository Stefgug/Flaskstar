FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd -m -u 1000 appuser

RUN pip install --no-cache-dir uv

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY . .

RUN chown -R 1000:1000 /app

EXPOSE 8080

ENV HOME=/home/appuser
USER 1000:1000

CMD ["uv", "run", "gunicorn", "-b", "0.0.0.0:8080", "app:app", "--workers", "2", "--threads", "4", "--timeout", "60"]

FROM python:3.10.7

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app
ENV REDIS_HOST=redis
ENV POSTGRES_SERVER=postgres
ENV REQUEST_LIMIT_PER_MINUTE=5
ENV FLASK_APP=app.py

RUN groupadd --system app && useradd --home-dir /app --system -g app app && chown app:app -R /app

RUN pip install -U pip wheel
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ./utils/wait_for_redis.py .
COPY ./app .
COPY app/migrations ./migrations
USER app
EXPOSE 5000
#RUN flask db upgrade
#CMD ["python3", "-m", "flask", "run"]

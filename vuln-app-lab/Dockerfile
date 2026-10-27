FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask>=3.0.0

COPY . /app

EXPOSE 5000

ENV DOCKER_CONTAINER=1
ENV FLASK_ENV=development

CMD ["python", "app.py", "--host", "0.0.0.0", "--port", "5000"]

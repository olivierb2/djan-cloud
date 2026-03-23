# Build frontend assets
FROM node:22-slim AS frontend

WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Python application
FROM python:3.13 AS app

RUN mkdir /app
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN pip install --upgrade pip
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app/

COPY --from=frontend /file/static/file/bundles/ /app/file/static/file/bundles/
COPY --from=frontend /file/static/file/webpack-stats.json /app/file/static/file/webpack-stats.json

RUN python manage.py collectstatic --noinput

EXPOSE 8000

# Nginx with static files
FROM nginx:alpine AS nginx

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=app /app/staticfiles/ /app/staticfiles/

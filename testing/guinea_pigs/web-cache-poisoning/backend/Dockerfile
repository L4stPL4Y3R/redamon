FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

ENV PYTHONUNBUFFERED=1
EXPOSE 5000
# gunicorn would be more production-like, but Flask's dev server keeps the demo
# single-dependency and logs every request, which is what we want for tracing.
CMD ["python", "app.py"]

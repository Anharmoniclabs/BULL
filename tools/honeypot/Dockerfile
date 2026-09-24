FROM python:3.12-slim
ENV PYTHONPATH=/app/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY src/bulldog /app/src/bulldog
COPY sensor.py dashboard.html test_sensor.py /app/
USER 1000:1000
CMD ["python", "/app/sensor.py", "--state", "/state"]

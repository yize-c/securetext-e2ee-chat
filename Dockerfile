FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY securetext.py .

# Run as a non-root user
RUN useradd --create-home appuser && chown appuser /app
USER appuser

ENTRYPOINT ["python", "securetext.py"]

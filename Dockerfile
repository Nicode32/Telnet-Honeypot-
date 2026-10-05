FROM python:3.11-slim

WORKDIR /app

COPY honeypot.py .

EXPOSE 2323

CMD ["python", "honeypot.py"]
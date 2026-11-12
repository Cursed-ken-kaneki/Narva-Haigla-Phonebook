FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask waitress
COPY server.py .
COPY index.html .
COPY fonts/ ./fonts/
COPY vendor/ ./vendor/
EXPOSE 80
CMD ["python", "server.py"]

FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask
COPY server.py .
COPY index.html .
EXPOSE 80
CMD ["python", "server.py"]

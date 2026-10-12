FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=10000 LAI_DATA_DIR=/var/lib/lai
WORKDIR /app
RUN groupadd --gid 10001 lai && useradd --uid 10001 --gid lai --create-home lai
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=lai:lai . /app
RUN mkdir -p /var/lib/lai && chown lai:lai /var/lib/lai && chmod 700 /var/lib/lai && chmod +x /app/entrypoint.sh
USER lai
EXPOSE 10000
CMD ["/app/entrypoint.sh"]

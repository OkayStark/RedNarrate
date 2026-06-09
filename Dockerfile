FROM python:3.11-slim

# WeasyPrint system libraries (pango/cairo/gdk-pixbuf) for PDF rendering.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
        libffi-dev shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir -e .

COPY . .
ENV REDNARRATE_DB_PATH=/app/data/rednarrate.db
RUN mkdir -p /app/data /app/output /app/chroma_db

EXPOSE 8000
CMD ["rednarrate", "serve", "--host", "0.0.0.0", "--port", "8000"]

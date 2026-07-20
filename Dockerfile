FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY . /app

# Install the package itself (not just requirements.txt) so the console script
# and packaged mappings/*.json resolve. Pass extras at build time, e.g.
#   docker build --build-arg OCINFERNO_EXTRAS=excel .
ARG OCINFERNO_EXTRAS=""
RUN python -m pip install --upgrade pip && \
    if [ -n "$OCINFERNO_EXTRAS" ]; then \
      pip install --no-cache-dir ".[${OCINFERNO_EXTRAS}]"; \
    else \
      pip install --no-cache-dir .; \
    fi

ENTRYPOINT ["ocinferno"]

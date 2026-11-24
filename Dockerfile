FROM python:3.12-slim AS build
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.12-slim
RUN useradd --system --uid 10001 --create-home webs
COPY --from=build /wheels /wheels
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels websentinel \
    && rm -rf /wheels \
    && mkdir -p /reports /data \
    && chown webs:webs /reports /data
USER webs
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /data
VOLUME ["/reports", "/data"]
ENTRYPOINT ["websentinel"]
